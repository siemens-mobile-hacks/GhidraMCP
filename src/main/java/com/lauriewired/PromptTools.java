package com.lauriewired;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

/** MCP prompts (analysis workflows with real context) and resources (program info, code). */
final class PromptTools {

    private static final int MAX_CODE_CHARS = 40_000;

    private final McpEnvironment env;
    private final DecompilerService decompiler;

    PromptTools(McpEnvironment env, DecompilerService decompiler) {
        this.env = env;
        this.decompiler = decompiler;
    }

    private static List<String[]> args(String... triples) {
        List<String[]> out = new ArrayList<>();
        for (int i = 0; i + 2 < triples.length; i += 3) {
            out.add(new String[] { triples[i], triples[i + 1], triples[i + 2] });
        }
        return out;
    }

    void register(McpServer mcp) {
        mcp.prompt("analyze_function",
            "Explain what a function does, with its decompiled code, callers and callees embedded.",
            args("name", "Function name (or use address)", "false",
                "address", "Function address", "false",
                "program", "Program name or path (default: current)", "false"),
            a -> {
                Function f = function(a);
                return "Analyze the function " + McpSupport.fqn(f) + " in " + f.getProgram().getName()
                    + ".\n\nExplain its purpose, inputs, outputs, side effects and notable logic. Propose a "
                    + "descriptive name, a C prototype, better variable names and comments; apply them with "
                    + "rename_function, set_function_prototype, update_variable and "
                    + "set_function_comment once you are confident.\n\n" + context(f);
            });

        mcp.prompt("identify_vulnerabilities",
            "Review a function for memory-safety and logic vulnerabilities, with its code embedded.",
            args("name", "Function name (or use address)", "false",
                "address", "Function address", "false",
                "program", "Program name or path (default: current)", "false"),
            a -> {
                Function f = function(a);
                return "Review " + McpSupport.fqn(f) + " for security vulnerabilities: buffer overflows, "
                    + "integer overflows/truncation, format strings, use-after-free/double free, unchecked "
                    + "return values, TOCTOU, injection and authentication/authorization flaws. For each "
                    + "finding give the address, the root cause, how attacker-controlled data reaches it "
                    + "(use get_callers, get_data_flow and get_xrefs_to to confirm), impact and a fix. Say "
                    + "explicitly when you find nothing.\n\n" + context(f);
            });

        mcp.prompt("reverse_engineer_binary",
            "Plan a full reverse-engineering pass over a program, starting from its metadata and entry points.",
            args("program", "Program name or path (default: current)", "false"),
            a -> {
                Program p = McpSupport.program(env, a.get("program"));
                StringBuilder sb = new StringBuilder();
                sb.append("Reverse engineer the program ").append(p.getDomainFile().getPathname()).append(".\n\n")
                    .append("Work in this order: (1) get_program_info and list_segments; (2) imports/exports "
                        + "and list_strings to find interesting functionality; (3) start at the entry points "
                        + "and main dispatch functions, using get_call_graph to map the structure; (4) "
                        + "decompile and name functions bottom-up (leaves first), recovering structures with "
                        + "create_struct/apply_data_type; (5) record findings with set_function_comment. "
                        + "Run analyze_program first if the program is not analyzed.\n\n");
                sb.append("Program facts:\n").append(programFacts(p));
                return sb.toString();
            });

        mcp.prompt("recover_structures",
            "Infer structure layouts from how a function accesses memory through pointers.",
            args("name", "Function name (or use address)", "false",
                "address", "Function address", "false",
                "program", "Program name or path (default: current)", "false"),
            a -> {
                Function f = function(a);
                return "Infer the structures that " + McpSupport.fqn(f) + " accesses through pointer "
                    + "arithmetic (patterns like *(int *)(param_1 + 0x10)). For each pointer give a C struct "
                    + "with field offsets, sizes, plausible names and types. Then create them with "
                    + "create_struct (use explicit offsets), apply them with update_variable/new_type and "
                    + "verify the improved decompilation.\n\n" + context(f);
            });

        mcp.resourceLister(() -> {
            List<String[]> out = new ArrayList<>();
            for (McpEnvironment.OpenProgram op : env.openPrograms()) {
                String path = op.program.getDomainFile().getPathname();
                out.add(new String[] { "ghidra://" + enc(path) + "/info", op.program.getName() + " info",
                    "Metadata of " + path, "text/plain" });
            }
            return out;
        });
        mcp.resourceTemplate("ghidra://{program}/info", "Program info",
            "Program metadata (program = URL-encoded project path)", "text/plain",
            v -> programFacts(McpSupport.program(env, v.get("program"))));
        mcp.resourceTemplate("ghidra://{program}/function/{function}/decompile", "Decompiled function",
            "C code of a function (function = name or address, URL-encoded)", "text/x-c",
            v -> decompile(resolve(v)));
        mcp.resourceTemplate("ghidra://{program}/function/{function}/disassembly", "Function disassembly",
            "Assembly of a function (function = name or address, URL-encoded)", "text/plain",
            v -> disassembly(resolve(v)));
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** Function by name first, then by address. */
    private Function resolve(Map<String, String> v) {
        Program p = McpSupport.program(env, v.get("program"));
        String f = v.get("function");
        try {
            return McpSupport.function(p, f, null);
        }
        catch (McpServer.InvalidArgumentException byName) {
            try {
                return McpSupport.function(p, null, f);
            }
            catch (McpServer.InvalidArgumentException byAddress) {
                throw byName;
            }
        }
    }

    private Function function(Map<String, String> a) {
        Program p = McpSupport.program(env, a.get("program"));
        return McpSupport.function(p, a.get("name"), a.get("address"));
    }

    private String decompile(Function f) {
        DecompileResults r = decompiler.decompile(f, 60);
        String c = r.getDecompiledFunction() == null ? "" : r.getDecompiledFunction().getC();
        return c.length() > MAX_CODE_CHARS ? c.substring(0, MAX_CODE_CHARS) + "\n/* ... truncated ... */" : c;
    }

    private String disassembly(Function f) {
        return McpSupport.onSwing(() -> {
            StringBuilder sb = new StringBuilder();
            InstructionIterator it = f.getProgram().getListing().getInstructions(f.getBody(), true);
            while (it.hasNext() && sb.length() < MAX_CODE_CHARS) {
                Instruction ins = it.next();
                sb.append(ins.getAddress()).append(": ").append(ins).append('\n');
            }
            return sb.toString().trim();
        });
    }

    private String context(Function f) {
        StringBuilder sb = new StringBuilder();
        sb.append("Function: ").append(McpSupport.fqn(f)).append(" at ").append(f.getEntryPoint())
            .append(" in ").append(f.getProgram().getDomainFile().getPathname()).append('\n');
        sb.append("Signature: ").append(f.getPrototypeString(false, false)).append('\n');
        McpSupport.onSwing(() -> {
            List<String> callers = new ArrayList<>();
            for (Function c : CodeAnalysisTools.callerSites(f).keySet()) callers.add(McpSupport.fqn(c));
            List<String> callees = new ArrayList<>();
            for (Function c : CodeAnalysisTools.calleeSites(f).keySet()) callees.add(McpSupport.fqn(c));
            sb.append("Callers: ").append(callers.isEmpty() ? "(none)" : String.join(", ", callers)).append('\n');
            sb.append("Callees: ").append(callees.isEmpty() ? "(none)" : String.join(", ", callees)).append('\n');
            return null;
        });
        sb.append("\nDecompiled code:\n```c\n").append(decompile(f)).append("\n```");
        return sb.toString();
    }

    private String programFacts(Program p) {
        return McpSupport.onSwing(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("Path: ").append(p.getDomainFile().getPathname()).append('\n');
            sb.append("Language: ").append(p.getLanguageID()).append(" / ")
                .append(p.getCompilerSpec().getCompilerSpecID()).append('\n');
            sb.append("Format: ").append(p.getExecutableFormat()).append('\n');
            sb.append("Image base: ").append(p.getImageBase()).append('\n');
            sb.append("Functions: ").append(p.getFunctionManager().getFunctionCount()).append('\n');
            sb.append("Analysis: ").append(AnalysisTools.analysisState(p)).append('\n');
            List<String> entries = new ArrayList<>();
            for (Symbol s : p.getSymbolTable().getAllSymbols(true)) {
                if (s.isExternalEntryPoint() && entries.size() < 20) entries.add(McpSupport.fqn(s) + " @ " + s.getAddress());
            }
            sb.append("Entry points: ").append(entries.isEmpty() ? "(none)" : String.join(", ", entries));
            return sb.toString();
        });
    }
}
