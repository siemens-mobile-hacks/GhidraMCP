package com.lauriewired;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitorAdapter;

/** Listing and running Ghidra scripts. */
final class ScriptTools {

    private static final Pattern CLASS_DECL =
        Pattern.compile("public\\s+class\\s+(\\w+)\\s+extends\\s+GhidraScript");
    private static final int MAX_OUTPUT = 200_000;

    private final McpEnvironment env;

    ScriptTools(McpEnvironment env) {
        this.env = env;
    }

    void register(McpServer mcp) {
        mcp.tool("list_scripts",
                "List runnable Ghidra scripts from the enabled script directories: name, category "
                    + "and path.")
            .optString("filter", "", "Case-insensitive substring of the name or category")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 200, "Maximum number of scripts")
            .handler(a -> list(a.str("filter"), a.integer("offset"), a.integer("limit")));

        mcp.tool("run_script",
                "Run a Ghidra script with the selected program as currentProgram and return its output "
                    + "(println) and errors. Pass name (an existing script, e.g. \"CountAndSaveStrings.java\") "
                    + "or source (Java source declaring 'public class X extends GhidraScript'; it is "
                    + "compiled from a temporary file in <ghidra settings>/ghidramcp_scripts, which is removed "
                    + "afterwards). The script may modify the program.")
            .optString("name", "", "Existing script file name")
            .optString("source", "", "Ad-hoc GhidraScript Java source")
            .optArray("args", McpServer.schema("string", null), "Script arguments (getScriptArgs())")
            .optInteger("timeout_seconds", 300, "Cancel the script after this many seconds")
            .program()
            .handler(this::run);
    }

    private String list(String filter, int offset, int limit) {
        String f = filter == null ? "" : filter.toLowerCase(Locale.ROOT);
        GhidraScriptUtil.acquireBundleHostReference();
        try {
            List<String> lines = new ArrayList<>();
            for (ResourceFile dir : GhidraScriptUtil.getEnabledScriptSourceDirectories()) {
                ResourceFile[] files = dir.listFiles();
                if (files == null) continue;
                for (ResourceFile file : files) {
                    if (file.isDirectory() || !GhidraScriptUtil.hasScriptProvider(file)) continue;
                    String category = "";
                    try {
                        category = String.join("/", GhidraScriptUtil.newScriptInfo(file).getCategory());
                    }
                    catch (Exception e) {
                        // metadata is optional
                    }
                    String line = file.getName() + "\t" + (category.isEmpty() ? "(uncategorized)" : category)
                        + "\t" + file.getAbsolutePath();
                    if (!f.isEmpty() && !line.toLowerCase(Locale.ROOT).contains(f)) continue;
                    lines.add(line);
                }
            }
            lines.sort(String.CASE_INSENSITIVE_ORDER);
            return McpSupport.page(lines, offset, limit);
        }
        finally {
            GhidraScriptUtil.releaseBundleHostReference();
        }
    }

    /** Serialized: concurrent runs would share (and remove) the temporary script bundle. */
    private synchronized String run(McpServer.Args a) throws Exception {
        String name = a.str("name").trim();
        String source = a.str("source");
        if (name.isEmpty() == source.isBlank()) throw McpSupport.fail("Pass exactly one of name or source");
        Program program = null;
        String selector = a.str("program");
        if (!selector.isBlank() || env.currentProgram() != null) {
            program = McpSupport.program(env, selector);
        }
        String[] args = toArgs(a.array("args"));

        ghidra.app.plugin.core.osgi.BundleHost host = GhidraScriptUtil.acquireBundleHostReference();
        File temp = null;
        ResourceFile tempBundle = null;
        try {
            ResourceFile file;
            if (!name.isEmpty()) {
                file = GhidraScriptUtil.findScriptByName(name);
                if (file == null) throw McpSupport.fail("Script not found: " + name + " (see list_scripts)");
            }
            else {
                Matcher m = CLASS_DECL.matcher(source);
                if (!m.find()) {
                    throw McpSupport.fail("source must declare 'public class <Name> extends GhidraScript'");
                }
                // A private source bundle directory: the user script directory is not always
                // registered with the OSGi bundle host (e.g. headless).
                File dir = new File(ghidra.framework.Application.getUserSettingsDirectory(), "ghidramcp_scripts");
                if (!dir.isDirectory() && !dir.mkdirs()) throw McpSupport.fail("Cannot create " + dir);
                tempBundle = new ResourceFile(dir);
                ghidra.app.plugin.core.osgi.GhidraBundle existing = host.getExistingGhidraBundle(tempBundle);
                if (existing != null && !(existing instanceof ghidra.app.plugin.core.osgi.GhidraSourceBundle)) {
                    host.remove(existing);
                    existing = null;
                }
                if (existing == null) host.add(tempBundle, true, false);
                host.enable(tempBundle);
                temp = new File(dir, m.group(1) + ".java");
                if (temp.exists()) {
                    File clash = temp;
                    temp = null;
                    throw McpSupport.fail("A script named " + clash.getName() + " already exists in " + dir
                        + "; rename the class in the source");
                }
                Files.writeString(temp.toPath(), source, StandardCharsets.UTF_8);
                file = new ResourceFile(temp);
            }
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(file);
            if (provider == null) throw McpSupport.fail("No script provider for " + file.getName());

            StringWriter out = new StringWriter();
            StringWriter err = new StringWriter();
            PrintWriter outWriter = new PrintWriter(out);
            PrintWriter errWriter = new PrintWriter(err);
            GhidraScript script = provider.getScriptInstance(file, errWriter);
            if (script == null) {
                errWriter.flush();
                throw McpSupport.fail("Could not load " + file.getName() + ":\n" + err);
            }
            script.setScriptArgs(args);
            PluginTool tool = env.activeProgramTool();
            GhidraState state = new GhidraState(tool, env.project(), program, null, null, null);
            TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
            int timeout = a.integer("timeout_seconds");
            Thread watchdog = new Thread(() -> {
                try {
                    Thread.sleep(Math.max(1, timeout) * 1000L);
                    monitor.cancel();
                }
                catch (InterruptedException e) {
                    // finished in time
                }
            }, "GhidraMCP-script-timeout");
            watchdog.setDaemon(true);
            watchdog.start();
            Throwable failure = null;
            long started = System.currentTimeMillis();
            try {
                script.execute(state, new ScriptControls(outWriter, errWriter, false, monitor));
            }
            catch (Throwable t) {
                failure = t;
            }
            finally {
                watchdog.interrupt();
                outWriter.flush();
                errWriter.flush();
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Script ").append(file.getName())
                .append(failure == null ? (monitor.isCancelled() ? " was cancelled" : " completed")
                    : " failed")
                .append(" in ").append(String.format("%.1f", (System.currentTimeMillis() - started) / 1000.0))
                .append(" s").append(program == null ? "" : " on " + program.getDomainFile().getPathname())
                .append('\n');
            sb.append("--- output ---\n").append(truncate(out.toString()));
            if (err.getBuffer().length() > 0) sb.append("\n--- errors ---\n").append(truncate(err.toString()));
            if (failure != null) {
                sb.append("\n--- exception ---\n").append(failure);
                throw McpSupport.fail(sb.toString());
            }
            return sb.toString().trim();
        }
        finally {
            if (temp != null && !temp.delete()) temp.deleteOnExit();
            if (tempBundle != null) {
                try {
                    host.remove(tempBundle); // keep it out of the user's Bundle Manager
                }
                catch (Exception e) {
                    // best effort
                }
            }
            GhidraScriptUtil.releaseBundleHostReference();
        }
    }

    private static String truncate(String s) {
        return s.length() > MAX_OUTPUT ? s.substring(0, MAX_OUTPUT) + "\n... (output truncated)" : s;
    }

    private static String[] toArgs(JsonArray arr) {
        String[] out = new String[arr.size()];
        int i = 0;
        for (JsonElement e : arr) out[i++] = e.getAsString();
        return out;
    }
}
