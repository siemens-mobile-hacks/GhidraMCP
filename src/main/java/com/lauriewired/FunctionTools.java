package com.lauriewired;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Function listing, details, navigation, deletion, variables and comments. */
final class FunctionTools {

    private final McpEnvironment env;
    private final DecompilerService decompiler;

    FunctionTools(McpEnvironment env, DecompilerService decompiler) {
        this.env = env;
        this.decompiler = decompiler;
    }

    void register(McpServer mcp) {
        mcp.tool("list_functions",
                "List functions as \"name at address\" (names are fully qualified, e.g. A::B::f). "
                    + "Optional filters: name_contains (case-insensitive), name_regex (Java regex on the "
                    + "qualified name), namespace (exact qualified namespace, \"\" = any), "
                    + "start_address/end_address (entry point range).")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 200, "Maximum number of results")
            .optString("name_contains", "", "Substring of the qualified name (case-insensitive)")
            .optString("name_regex", "", "Regular expression matched against the qualified name")
            .optString("namespace", "", "Only functions in this namespace (use \"Global\" for global)")
            .optString("start_address", "", "Lowest entry point")
            .optString("end_address", "", "Highest entry point")
            .program()
            .handler(this::listFunctions);

        mcp.tool("get_function",
                "Details of a function by name or address (an address inside the body is accepted): "
                    + "qualified name, signature, calling convention, parameters with storage, return type, "
                    + "body ranges and size, stack frame, flags (thunk, varargs, noreturn, inline, "
                    + "external), comment and caller/callee counts.")
            .optString("name", "", "Function name (qualified names accepted)")
            .optString("address", "", "Entry point or any address inside the function")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                return details(McpSupport.function(p, a.str("name"), a.str("address")));
            });

        mcp.tool("get_adjacent_function",
                "The next or previous function (by entry point) relative to an address.")
            .string("address", "Reference address")
            .optString("direction", "next", "\"next\" or \"prev\"")
            .program()
            .handler(a -> adjacent(McpSupport.program(env, a.str("program")), a.str("address"),
                a.str("direction")));

        mcp.tool("delete_function",
                "Delete the function definition at an address or with a name. Instructions are kept; "
                    + "the entry label remains as a plain label.")
            .optString("name", "", "Function name")
            .optString("address", "", "Entry point or address inside the function")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                return delete(McpSupport.function(p, a.str("name"), a.str("address")));
            });

        mcp.tool("list_function_variables",
                "Parameters and local variables of a function with type, storage and source. "
                    + "include_decompiler=true adds variables that only exist in the decompiler output.")
            .optString("name", "", "Function name")
            .optString("address", "", "Entry point or address inside the function")
            .optBoolean("include_decompiler", false, "Also list decompiler (high) variables")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                return variables(McpSupport.function(p, a.str("name"), a.str("address")),
                    a.bool("include_decompiler"));
            });

        mcp.tool("update_variable",
                "Rename and/or retype a parameter or local variable in one transaction. Works for "
                    + "listing variables and for variables that only exist in the decompiler output.")
            .optString("function_name", "", "Function name")
            .optString("function_address", "", "Function entry or address inside it")
            .string("variable", "Current variable name")
            .optString("new_name", "", "New name")
            .optString("new_type", "", "New data type, e.g. \"char *\" or \"MyStruct\"")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                Function f = McpSupport.function(p, a.str("function_name"), a.str("function_address"));
                return updateVariable(f, a.str("variable"), a.str("new_name"), a.str("new_type"));
            });

        mcp.tool("set_function_comment",
                "Set the function's comment (the plate comment shown above the function in the listing "
                    + "and at the top of the decompiler output). An empty comment clears it.")
            .optString("name", "", "Function name")
            .optString("address", "", "Function entry or address inside it")
            .string("comment", "Comment text")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                Function f = McpSupport.function(p, a.str("name"), a.str("address"));
                String c = a.str("comment");
                McpSupport.write(p, "Set function comment", () -> {
                    f.setComment(c.isEmpty() ? null : c);
                    return null;
                });
                return (c.isEmpty() ? "Cleared comment of " : "Set comment of ") + McpSupport.fqn(f);
            });

        mcp.tool("rename_function",
                "Rename a function found by current name or address. new_name may be qualified: A::B::f "
                    + "moves it into namespace A::B (created if missing), ::f to the global namespace.")
            .optString("old_name", "", "Current function name (qualified names accepted)")
            .optString("address", "", "Function entry or address inside it")
            .string("new_name", "New name")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                return rename(McpSupport.function(p, a.str("old_name"), a.str("address")), a.str("new_name"));
            });

    }

    // ------------------------------------------------------------------

    private String listFunctions(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        String contains = a.str("name_contains").toLowerCase();
        Pattern regex = McpSupport.regex(a.str("name_regex"));
        String ns = a.str("namespace");
        Address start = a.str("start_address").isEmpty() ? null : McpSupport.address(p, a.str("start_address"));
        Address end = a.str("end_address").isEmpty() ? null : McpSupport.address(p, a.str("end_address"));
        return McpSupport.onSwing(() -> {
            List<String> lines = new ArrayList<>();
            FunctionIterator it = start == null ? p.getFunctionManager().getFunctions(true)
                : p.getFunctionManager().getFunctions(start, true);
            for (Function f : it) {
                if (end != null && f.getEntryPoint().compareTo(end) > 0) break;
                String q = McpSupport.fqn(f);
                if (!contains.isEmpty() && !q.toLowerCase().contains(contains)) continue;
                if (regex != null && !regex.matcher(q).find()) continue;
                if (!ns.isEmpty()) {
                    String fns = McpSupport.namespacePath(f.getParentNamespace());
                    if (ns.equals("Global") ? !fns.isEmpty() : !fns.equals(ns)) continue;
                }
                lines.add(q + " at " + f.getEntryPoint());
            }
            return McpSupport.page(lines, a.integer("offset"), a.integer("limit"));
        });
    }

    private String details(Function f) {
        return McpSupport.onSwing(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("Function: ").append(McpSupport.fqn(f)).append(" at ").append(f.getEntryPoint()).append('\n');
            sb.append("Signature: ").append(f.getPrototypeString(false, false)).append('\n');
            sb.append("Calling convention: ").append(f.getCallingConventionName()).append('\n');
            sb.append("Return: ").append(f.getReturnType().getDisplayName())
                .append(" @ ").append(f.getReturn().getVariableStorage()).append('\n');
            Parameter[] params = f.getParameters();
            sb.append("Parameters: ").append(params.length == 0 ? "(none)" : "").append('\n');
            for (Parameter prm : params) {
                sb.append("  ").append(prm.getOrdinal()).append(": ").append(prm.getDataType().getDisplayName())
                    .append(' ').append(prm.getName()).append(" @ ").append(prm.getVariableStorage()).append('\n');
            }
            sb.append("Body: ");
            List<String> ranges = new ArrayList<>();
            for (AddressRange r : f.getBody()) ranges.add(r.getMinAddress() + "-" + r.getMaxAddress());
            sb.append(String.join(", ", ranges)).append(" (").append(f.getBody().getNumAddresses())
                .append(" bytes)\n");
            sb.append("Stack frame: size ").append(f.getStackFrame().getFrameSize())
                .append(", locals ").append(f.getStackFrame().getLocalSize())
                .append(", purge ").append(f.getStackPurgeSize()).append('\n');
            List<String> flags = new ArrayList<>();
            if (f.isThunk()) flags.add("thunk -> " + McpSupport.fqn(f.getThunkedFunction(true)));
            if (f.hasVarArgs()) flags.add("varargs");
            if (f.hasNoReturn()) flags.add("noreturn");
            if (f.isInline()) flags.add("inline");
            if (f.isExternal()) flags.add("external");
            if (f.hasCustomVariableStorage()) flags.add("custom storage");
            sb.append("Flags: ").append(flags.isEmpty() ? "(none)" : String.join(", ", flags)).append('\n');
            sb.append("Signature source: ").append(f.getSignatureSource()).append('\n');
            Set<Function> callers = f.getCallingFunctions(TaskMonitor.DUMMY);
            Set<Function> callees = f.getCalledFunctions(TaskMonitor.DUMMY);
            sb.append("Callers: ").append(callers.size()).append(", callees: ").append(callees.size()).append('\n');
            String comment = f.getComment();
            sb.append("Comment: ").append(comment == null ? "(none)" : comment);
            return sb.toString();
        });
    }

    private String adjacent(Program p, String address, String direction) {
        Address a = McpSupport.address(p, address);
        boolean next = direction == null || !direction.trim().equalsIgnoreCase("prev");
        if (direction != null && !direction.isBlank()
                && !direction.trim().equalsIgnoreCase("next") && !direction.trim().equalsIgnoreCase("prev")) {
            throw McpSupport.fail("direction must be \"next\" or \"prev\"");
        }
        return McpSupport.onSwing(() -> {
            FunctionIterator it = p.getFunctionManager().getFunctions(a, next);
            while (it.hasNext()) {
                Function f = it.next();
                if (f.getEntryPoint().equals(a)) continue;
                return (next ? "Next" : "Previous") + " function: " + McpSupport.fqn(f) + " at " + f.getEntryPoint();
            }
            throw McpSupport.fail("No " + (next ? "next" : "previous") + " function from " + a);
        });
    }

    private String delete(Function f) {
        Program p = f.getProgram();
        String name = McpSupport.fqn(f);
        Address entry = f.getEntryPoint();
        McpSupport.write(p, "Delete function", () -> {
            if (!p.getFunctionManager().removeFunction(entry)) {
                throw McpSupport.fail("Ghidra refused to delete " + name);
            }
            return null;
        });
        return "Deleted function " + name + " at " + entry;
    }

    private String variables(Function f, boolean includeDecompiler) {
        StringBuilder sb = new StringBuilder();
        McpSupport.onSwing(() -> {
            sb.append("Function: ").append(McpSupport.fqn(f)).append(" at ").append(f.getEntryPoint()).append('\n');
            for (Parameter prm : f.getParameters()) {
                sb.append("param ").append(prm.getOrdinal()).append(": ").append(describe(prm)).append('\n');
            }
            for (Variable v : f.getLocalVariables()) {
                sb.append("local: ").append(describe(v)).append('\n');
            }
            return null;
        });
        if (includeDecompiler) {
            DecompileResults r = decompiler.decompile(f, 60);
            HighFunction hf = r.getHighFunction();
            if (hf != null) {
                Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
                while (it.hasNext()) {
                    HighSymbol hs = it.next();
                    sb.append("decompiler ").append(hs.isParameter() ? "param" : "local").append(": ")
                        .append(hs.getDataType().getDisplayName()).append(' ').append(hs.getName())
                        .append(" @ ").append(hs.getStorage())
                        .append(hs.getSymbol() == null ? " (not in listing)" : "").append('\n');
                }
            }
        }
        return sb.toString().trim();
    }

    private static String describe(Variable v) {
        return v.getDataType().getDisplayName() + " " + v.getName() + " @ " + v.getVariableStorage()
            + " (" + v.getSource() + ")" + (v.getComment() == null ? "" : " // " + v.getComment());
    }

    private String updateVariable(Function f, String variable, String newName, String newType) {
        Program p = f.getProgram();
        if (variable == null || variable.isBlank()) throw McpSupport.fail("variable is required");
        boolean rename = newName != null && !newName.isBlank();
        boolean retype = newType != null && !newType.isBlank();
        if (!rename && !retype) throw McpSupport.fail("Pass new_name and/or new_type");
        if (rename && newName.contains("::")) throw McpSupport.fail("Variable names cannot contain '::'");
        DataType dt = retype ? McpSupport.dataType(p, newType) : null;

        Variable target = null;
        for (Variable v : f.getAllVariables()) {
            if (v.getName().equals(variable)) {
                target = v;
                break;
            }
        }
        if (target != null) {
            Variable v = target;
            McpSupport.write(p, "Update variable", () -> {
                if (retype) v.setDataType(dt, SourceType.USER_DEFINED);
                if (rename) v.setName(newName.trim(), SourceType.USER_DEFINED);
                return null;
            });
            return "Updated " + (v instanceof Parameter ? "parameter " : "local ") + variable + " in "
                + McpSupport.fqn(f) + ": " + v.getDataType().getDisplayName() + " " + v.getName();
        }

        DecompileResults r = decompiler.decompile(f, 60);
        HighFunction hf = r.getHighFunction();
        HighSymbol hs = null;
        if (hf != null) {
            Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (s.getName().equals(variable)) {
                    hs = s;
                    break;
                }
            }
        }
        if (hs == null) {
            throw McpSupport.fail("Variable " + variable + " not found in " + McpSupport.fqn(f)
                + " (see list_function_variables with include_decompiler=true)");
        }
        HighSymbol symbol = hs;
        McpSupport.write(p, "Update decompiler variable", () -> {
            HighFunctionDBUtil.updateDBVariable(symbol, rename ? newName.trim() : null, dt,
                SourceType.USER_DEFINED);
            return null;
        });
        return "Updated decompiler variable " + variable + " in " + McpSupport.fqn(f)
            + (rename ? " -> " + newName.trim() : "") + (retype ? " : " + dt.getDisplayName() : "");
    }

    private String rename(Function f, String newName) {
        Program p = f.getProgram();
        String old = McpSupport.fqn(f);
        McpSupport.write(p, "Rename function", () -> {
            McpSupport.applyName(p, f.getSymbol(), newName);
            return null;
        });
        return "Renamed function " + old + " -> " + McpSupport.fqn(f);
    }
}
