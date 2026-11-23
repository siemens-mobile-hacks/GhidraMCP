package com.lauriewired;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Auto-analysis: run, status, analyzer listing and options. */
final class AnalysisTools {

    /** Last analysis run started through MCP, per program. */
    private static final class Run {
        volatile String state = "running";
        volatile String error;
        final long started = System.currentTimeMillis();
        volatile long finished;
        volatile String taskTimes = "";
        volatile TaskMonitor monitor;
    }

    private static final Map<Program, Run> runs = Collections.synchronizedMap(new java.util.WeakHashMap<>());

    private final McpEnvironment env;

    AnalysisTools(McpEnvironment env) {
        this.env = env;
    }

    void register(McpServer mcp) {
        mcp.tool("analyze_program",
                "Run Ghidra auto-analysis on a program (all enabled analyzers over the whole program). "
                    + "wait=true blocks until analysis finishes (or timeout_seconds elapses, which cancels "
                    + "it); wait=false starts it in the background — poll get_analysis_status. "
                    + "'analyzers' enables/disables analyzers for this run, e.g. "
                    + "[{\"name\": \"Decompiler Parameter ID\", \"enabled\": true}].")
            .program()
            .optBoolean("wait", true, "Block until analysis completes")
            .optInteger("timeout_seconds", 1800, "Cancel analysis after this many seconds when wait=true")
            .optArray("analyzers", McpServer.objectSchema("name", "string", "enabled", "boolean"),
                "Analyzers to enable/disable before running")
            .handler(a -> analyze(McpSupport.program(env, a.str("program")), a.bool("wait"),
                a.integer("timeout_seconds"), a.array("analyzers")));

        mcp.tool("get_analysis_status",
                "Auto-analysis state of a program: whether it was analyzed, whether analysis is running "
                    + "now, and the result and per-analyzer timings of the last run started via MCP.")
            .program()
            .handler(a -> status(McpSupport.program(env, a.str("program"))));

        mcp.tool("cancel_analysis", "Cancel the running or queued auto-analysis of a program.")
            .program()
            .handler(a -> cancel(McpSupport.program(env, a.str("program"))));

        mcp.tool("list_analyzers",
                "List the program's analyzers with enabled state and description. include_options=true "
                    + "also lists each analyzer's settings (name = value).")
            .program()
            .optBoolean("include_options", false, "Include analyzer settings")
            .optString("filter", "", "Case-insensitive substring filter on the analyzer name")
            .handler(a -> listAnalyzers(McpSupport.program(env, a.str("program")),
                a.bool("include_options"), a.str("filter")));

        mcp.tool("set_analyzer_options",
                "Set analysis options of a program. Each item is {\"name\": ..., \"value\": ...}; the "
                    + "name is an analyzer name (value true/false enables it) or an analyzer setting "
                    + "\"Analyzer Name.Setting\" as shown by list_analyzers(include_options=true).")
            .program()
            .array("options", McpServer.objectSchema("name", "string", "value", "string"),
                "Options to set")
            .handler(a -> setOptions(McpSupport.program(env, a.str("program")), a.array("options")));
    }

    static String analysisState(Program p) {
        String base = GhidraProgramUtilities.isAnalyzed(p) ? "analyzed" : "not analyzed";
        Run run = runs.get(p);
        boolean running = AutoAnalysisManager.getAnalysisManager(p).isAnalyzing();
        if (running || (run != null && run.state.equals("running"))) return base + ", analysis running";
        return base;
    }

    private String analyze(Program program, boolean wait, int timeoutSeconds, JsonArray analyzers)
            throws Exception {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        Run previous = runs.get(program);
        if (mgr.isAnalyzing() || (previous != null && previous.state.equals("running"))) {
            throw McpSupport.fail("Analysis is already running for " + program.getName()
                + "; use get_analysis_status or cancel_analysis");
        }
        if (analyzers.size() > 0) {
            applyOptions(program, toNameValue(analyzers, "enabled"));
        }
        Run run = new Run();
        TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        run.monitor = monitor;
        runs.put(program, run);

        Runnable job = () -> {
            int tx = program.startTransaction("Auto Analysis (MCP)");
            boolean ok = false;
            try {
                mgr.initializeOptions();
                mgr.reAnalyzeAll(null);
                mgr.startAnalysis(monitor);
                if (monitor.isCancelled()) {
                    run.state = "cancelled";
                }
                else {
                    GhidraProgramUtilities.markProgramAnalyzed(program);
                    run.state = "completed";
                }
                ok = true;
            }
            catch (Throwable t) {
                run.state = "failed";
                run.error = t.toString();
            }
            finally {
                program.endTransaction(tx, ok);
                run.finished = System.currentTimeMillis();
                run.taskTimes = mgr.getTaskTimesString();
            }
        };

        if (!wait) {
            Thread t = new Thread(job, "GhidraMCP-analysis-" + program.getName());
            t.setDaemon(true);
            t.start();
            return "Analysis started in the background for " + program.getDomainFile().getPathname()
                + "; poll get_analysis_status";
        }
        Thread watchdog = null;
        if (timeoutSeconds > 0) {
            watchdog = new Thread(() -> {
                try {
                    Thread.sleep(timeoutSeconds * 1000L);
                    monitor.cancel();
                }
                catch (InterruptedException e) {
                    // finished in time
                }
            }, "GhidraMCP-analysis-timeout");
            watchdog.setDaemon(true);
            watchdog.start();
        }
        try {
            job.run();
        }
        finally {
            if (watchdog != null) watchdog.interrupt();
        }
        if (run.state.equals("failed")) throw McpSupport.fail("Analysis failed: " + run.error);
        return describe(program, run, false);
    }

    private String describe(Program program, Run run, boolean withHeader) {
        StringBuilder sb = new StringBuilder();
        if (withHeader) {
            sb.append("Program: ").append(program.getDomainFile().getPathname()).append('\n')
                .append("State: ").append(analysisState(program)).append('\n');
        }
        if (run == null) {
            sb.append("No analysis was started through MCP for this program in this session");
            return sb.toString();
        }
        long end = run.finished == 0 ? System.currentTimeMillis() : run.finished;
        sb.append("Last MCP run: ").append(run.state).append(" after ")
            .append(String.format("%.1f", (end - run.started) / 1000.0)).append(" s\n");
        if (run.error != null) sb.append("Error: ").append(run.error).append('\n');
        sb.append("Functions: ").append(program.getFunctionManager().getFunctionCount()).append('\n');
        if (!run.taskTimes.isBlank()) sb.append("Analyzer timings:\n").append(run.taskTimes.trim());
        return sb.toString().trim();
    }

    private String status(Program program) {
        return describe(program, runs.get(program), true);
    }

    private String cancel(Program program) {
        Run run = runs.get(program);
        boolean any = false;
        if (run != null && run.monitor != null && run.state.equals("running")) {
            run.monitor.cancel();
            any = true;
        }
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        if (mgr.isAnalyzing()) any = true;
        mgr.cancelQueuedTasks();
        return any ? "Cancellation requested for " + program.getName() : "No analysis is running for " + program.getName();
    }

    private String listAnalyzers(Program program, boolean includeOptions, String filter) {
        return McpSupport.onSwing(() -> {
            AutoAnalysisManager.getAnalysisManager(program).registerOptions();
            Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> names = new ArrayList<>(opts.getOptionNames());
            Collections.sort(names);
            String f = filter == null ? "" : filter.toLowerCase();
            List<String> lines = new ArrayList<>();
            for (String name : names) {
                if (name.contains(".")) continue;
                if (opts.getType(name) != OptionType.BOOLEAN_TYPE) continue;
                if (!f.isEmpty() && !name.toLowerCase().contains(f)) continue;
                boolean enabled = opts.getBoolean(name, false);
                String desc = opts.getDescription(name);
                lines.add((enabled ? "[x] " : "[ ] ") + name
                    + (desc == null || desc.isBlank() ? "" : " — " + desc.replaceAll("\\s+", " ").trim()));
                if (includeOptions) {
                    for (String sub : names) {
                        if (!sub.startsWith(name + ".")) continue;
                        Object v = opts.getObject(sub, null);
                        lines.add("      " + sub + " = " + v + "  (" + opts.getType(sub) + ")");
                    }
                }
            }
            return lines.isEmpty() ? "(no analyzers match)" : String.join("\n", lines);
        });
    }

    private static List<String[]> toNameValue(JsonArray items, String valueKey) {
        List<String[]> out = new ArrayList<>();
        for (JsonElement e : items) {
            if (!e.isJsonObject()) throw McpSupport.fail("Each item must be an object");
            JsonObject o = e.getAsJsonObject();
            if (!o.has("name")) throw McpSupport.fail("Each item needs a 'name'");
            JsonElement v = o.has(valueKey) ? o.get(valueKey) : o.get("value");
            if (v == null || v.isJsonNull()) throw McpSupport.fail("Item " + o.get("name") + " needs a value");
            out.add(new String[] { o.get("name").getAsString(), v.getAsString() });
        }
        return out;
    }

    private String setOptions(Program program, JsonArray items) {
        List<String> applied = applyOptions(program, toNameValue(items, "value"));
        return "Set " + applied.size() + " option(s):\n  " + String.join("\n  ", applied);
    }

    private List<String> applyOptions(Program program, List<String[]> items) {
        AutoAnalysisManager.getAnalysisManager(program).registerOptions();
        return McpSupport.write(program, "Set analysis options (MCP)", () -> {
            Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> applied = new ArrayList<>();
            for (String[] nv : items) {
                String name = nv[0];
                String value = nv[1];
                if (!opts.contains(name)) {
                    throw McpSupport.fail("Unknown analysis option: " + name + " (see list_analyzers)");
                }
                OptionType type = opts.getType(name);
                switch (type) {
                    case BOOLEAN_TYPE:
                        if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                            throw McpSupport.fail(name + " expects true/false, got " + value);
                        }
                        opts.setBoolean(name, Boolean.parseBoolean(value));
                        break;
                    case INT_TYPE:
                        opts.setInt(name, Integer.decode(value));
                        break;
                    case LONG_TYPE:
                        opts.setLong(name, Long.decode(value));
                        break;
                    case DOUBLE_TYPE:
                        opts.setDouble(name, Double.parseDouble(value));
                        break;
                    case FLOAT_TYPE:
                        opts.setFloat(name, Float.parseFloat(value));
                        break;
                    case STRING_TYPE:
                        opts.setString(name, value);
                        break;
                    case ENUM_TYPE: {
                        Object current = opts.getObject(name, null);
                        if (!(current instanceof Enum)) throw McpSupport.fail("Cannot set enum option " + name);
                        Enum<?> parsed = parseEnum((Enum<?>) current, value);
                        setEnum(opts, name, parsed);
                        break;
                    }
                    default:
                        throw McpSupport.fail("Option " + name + " has unsupported type " + type);
                }
                applied.add(name + " = " + opts.getObject(name, null));
            }
            return applied;
        });
    }

    private static Enum<?> parseEnum(Enum<?> current, String value) {
        for (Object c : current.getDeclaringClass().getEnumConstants()) {
            Enum<?> e = (Enum<?>) c;
            if (e.name().equalsIgnoreCase(value) || e.toString().equalsIgnoreCase(value)) return e;
        }
        List<String> allowed = new ArrayList<>();
        for (Object c : current.getDeclaringClass().getEnumConstants()) allowed.add(c.toString());
        throw McpSupport.fail("Invalid value " + value + "; allowed: " + String.join(", ", allowed));
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static void setEnum(Options opts, String name, Enum value) {
        opts.setEnum(name, value);
    }
}
