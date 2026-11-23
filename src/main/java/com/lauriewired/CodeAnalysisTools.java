package com.lauriewired;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

/** Cross references, callers/callees, call graphs, data flow and scalar search. */
final class CodeAnalysisTools {

    private static final String REF_TYPES = "CALL, JUMP, FLOW, READ, WRITE, DATA, POINTER, or an exact "
        + "Ghidra reference type name such as UNCONDITIONAL_CALL";

    private final McpEnvironment env;
    private final DecompilerService decompiler;

    CodeAnalysisTools(McpEnvironment env, DecompilerService decompiler) {
        this.env = env;
        this.decompiler = decompiler;
    }

    void register(McpServer mcp) {
        mcp.tool("get_xrefs_to",
                "References to an address: \"From <addr> in <function> [TYPE]\". ref_type filters by "
                    + REF_TYPES + ".")
            .string("address", "Target address")
            .optString("ref_type", "", "Reference type filter")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of references")
            .program()
            .handler(a -> xrefs(a, true));

        mcp.tool("get_xrefs_from",
                "References from an address: \"To <addr> (<target>) [TYPE]\". ref_type filters by "
                    + REF_TYPES + ".")
            .string("address", "Source address")
            .optString("ref_type", "", "Reference type filter")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of references")
            .program()
            .handler(a -> xrefs(a, false));

        mcp.tool("get_callers",
                "Functions that call a function, with the call sites: \"caller @ entry (calls at ...)\".")
            .optString("name", "", "Function name")
            .optString("address", "", "Function entry or address inside it")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                return callers(McpSupport.function(p, a.str("name"), a.str("address")));
            });

        mcp.tool("get_callees",
                "Functions called by a function (whole body scanned), with call sites: "
                    + "\"callee @ entry (from ...)\". Thunks and external functions are included.")
            .optString("name", "", "Function name")
            .optString("address", "", "Function entry or address inside it")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                return callees(McpSupport.function(p, a.str("name"), a.str("address")));
            });

        mcp.tool("get_call_graph",
                "Call graph rooted at a function. direction: callees (default), callers or both. "
                    + "format: tree (indented) or edges (\"from -> to @ call_site\"). Bounded by "
                    + "max_depth and max_nodes; already visited functions are marked (seen).")
            .optString("name", "", "Root function name")
            .optString("address", "", "Root function address")
            .optString("direction", "callees", "callees, callers or both")
            .optInteger("max_depth", 3, "Maximum depth")
            .optInteger("max_nodes", 200, "Maximum number of functions")
            .optString("format", "tree", "tree or edges")
            .program()
            .handler(this::callGraph);

        mcp.tool("get_data_flow",
                "Decompiler-based data-flow slice. Pick the start value by decompiler variable name "
                    + "(variable) or by an instruction address (optionally a register used/defined there). "
                    + "direction=forward lists the P-code operations the value flows into; backward lists "
                    + "those it is computed from. Each step shows address, instruction and P-code.")
            .optString("function_name", "", "Function name (default: the function containing address)")
            .optString("address", "", "Instruction address of the start value")
            .optString("variable", "", "Decompiler variable name (see list_function_variables)")
            .optString("register", "", "Register at the address, e.g. RDI or r0")
            .optString("direction", "forward", "forward or backward")
            .optInteger("max_steps", 50, "Maximum number of P-code operations to list")
            .program()
            .handler(this::dataFlow);

        mcp.tool("search_scalars",
                "Find instructions with a constant operand (like Search > For Scalars). value accepts "
                    + "decimal, 0x hex and negative numbers. in_function limits to functions whose name "
                    + "contains the text; to_function keeps matches where "
                    + "the first call within 10 instructions targets a function whose name contains the text "
                    + "(e.g. the size passed to memset). "
                    + "Large unfiltered scans stop after time_budget_seconds and say so.")
            .string("value", "Value to search for")
            .optString("in_function", "", "Only inside functions whose name contains this")
            .optString("to_function", "", "Only when a following call targets a function containing this")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of results")
            .optInteger("time_budget_seconds", 20, "Stop scanning after this many seconds")
            .program()
            .handler(this::searchScalars);
    }

    // ------------------------------------------------------------------
    // Cross references
    // ------------------------------------------------------------------

    static boolean refTypeMatches(RefType t, String filter) {
        if (filter == null || filter.isBlank()) return true;
        String f = filter.trim().toUpperCase(Locale.ROOT);
        switch (f) {
            case "CALL":
                return t.isCall();
            case "JUMP":
                return t.isJump();
            case "FLOW":
                return t.isFlow();
            case "READ":
                return t.isRead();
            case "WRITE":
                return t.isWrite();
            case "DATA":
                return t.isData();
            case "POINTER":
                return t.isData() || t == RefType.DATA_IND;
            default:
                return t.getName().equalsIgnoreCase(f);
        }
    }

    private String xrefs(McpServer.Args a, boolean to) {
        Program p = McpSupport.program(env, a.str("program"));
        Address addr = McpSupport.address(p, a.str("address"));
        String filter = a.str("ref_type");
        return McpSupport.onSwing(() -> {
            List<String> lines = new ArrayList<>();
            if (to) {
                ReferenceIterator it = p.getReferenceManager().getReferencesTo(addr);
                while (it.hasNext()) {
                    Reference r = it.next();
                    if (!refTypeMatches(r.getReferenceType(), filter)) continue;
                    Function f = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    lines.add("From " + r.getFromAddress() + (f == null ? "" : " in " + McpSupport.fqn(f))
                        + " [" + r.getReferenceType().getName() + "]");
                }
            }
            else {
                for (Reference r : p.getReferenceManager().getReferencesFrom(addr)) {
                    if (!refTypeMatches(r.getReferenceType(), filter)) continue;
                    lines.add("To " + r.getToAddress() + describeTarget(p, r.getToAddress())
                        + " [" + r.getReferenceType().getName() + "]");
                }
            }
            return McpSupport.page(lines, a.integer("offset"), a.integer("limit"));
        });
    }

    private static String describeTarget(Program p, Address a) {
        Function f = p.getFunctionManager().getFunctionAt(a);
        if (f != null) return " (function " + McpSupport.fqn(f) + ")";
        Data d = p.getListing().getDataAt(a);
        Symbol s = p.getSymbolTable().getPrimarySymbol(a);
        if (d != null && d.isDefined()) {
            return " (data " + (s == null ? "" : McpSupport.fqn(s) + " ") + d.getDataType().getDisplayName() + ")";
        }
        return s == null ? "" : " (" + McpSupport.fqn(s) + ")";
    }

    // ------------------------------------------------------------------
    // Callers / callees / call graph
    // ------------------------------------------------------------------

    /** Callees with their call sites, in body order. */
    static Map<Function, List<Address>> calleeSites(Function f) {
        Program p = f.getProgram();
        Map<Function, List<Address>> out = new LinkedHashMap<>();
        InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (Reference r : ins.getReferencesFrom()) {
                if (!r.getReferenceType().isCall()) continue;
                Function callee = p.getFunctionManager().getFunctionAt(r.getToAddress());
                if (callee == null) {
                    // call through a pointer to an external/thunk location
                    Data d = p.getListing().getDataAt(r.getToAddress());
                    if (d != null && d.getValue() instanceof Address) {
                        callee = p.getFunctionManager().getFunctionAt((Address) d.getValue());
                    }
                }
                if (callee == null) continue;
                out.computeIfAbsent(callee, k -> new ArrayList<>()).add(ins.getAddress());
            }
        }
        return out;
    }

    /** Callers with their call sites. */
    static Map<Function, List<Address>> callerSites(Function f) {
        Program p = f.getProgram();
        Map<Function, List<Address>> out = new LinkedHashMap<>();
        List<Address> targets = new ArrayList<>();
        targets.add(f.getEntryPoint());
        // calls may go through thunks of this function
        for (Address thunk : f.getFunctionThunkAddresses(true) == null ? new Address[0]
                : f.getFunctionThunkAddresses(true)) {
            targets.add(thunk);
        }
        for (Address target : targets) {
            ReferenceIterator it = p.getReferenceManager().getReferencesTo(target);
            while (it.hasNext()) {
                Reference r = it.next();
                if (!r.getReferenceType().isCall()) continue;
                Function caller = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (caller == null) continue;
                out.computeIfAbsent(caller, k -> new ArrayList<>()).add(r.getFromAddress());
            }
        }
        return out;
    }

    private static String sites(List<Address> list) {
        List<String> s = new ArrayList<>();
        for (Address a : list) s.add(a.toString());
        return String.join(", ", s);
    }

    private String callers(Function f) {
        return McpSupport.onSwing(() -> {
            Map<Function, List<Address>> m = callerSites(f);
            if (m.isEmpty()) return "No callers of " + McpSupport.fqn(f);
            StringBuilder sb = new StringBuilder("Callers of " + McpSupport.fqn(f) + ":\n");
            for (Map.Entry<Function, List<Address>> e : m.entrySet()) {
                sb.append("  ").append(McpSupport.fqn(e.getKey())).append(" @ ").append(e.getKey().getEntryPoint())
                    .append(" (calls at ").append(sites(e.getValue())).append(")\n");
            }
            return sb.toString().trim();
        });
    }

    private String callees(Function f) {
        return McpSupport.onSwing(() -> {
            Map<Function, List<Address>> m = calleeSites(f);
            if (m.isEmpty()) return McpSupport.fqn(f) + " calls no functions";
            StringBuilder sb = new StringBuilder("Callees of " + McpSupport.fqn(f) + ":\n");
            for (Map.Entry<Function, List<Address>> e : m.entrySet()) {
                Function c = e.getKey();
                sb.append("  ").append(McpSupport.fqn(c)).append(" @ ").append(c.getEntryPoint())
                    .append(c.isExternal() ? " [external]" : c.isThunk() ? " [thunk]" : "")
                    .append(" (from ").append(sites(e.getValue())).append(")\n");
            }
            return sb.toString().trim();
        });
    }

    private String callGraph(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Function root = McpSupport.function(p, a.str("name"), a.str("address"));
        String dir = a.str("direction").trim().toLowerCase(Locale.ROOT);
        if (!dir.equals("callees") && !dir.equals("callers") && !dir.equals("both")) {
            throw McpSupport.fail("direction must be callees, callers or both");
        }
        String format = a.str("format").trim().toLowerCase(Locale.ROOT);
        if (!format.equals("tree") && !format.equals("edges")) throw McpSupport.fail("format must be tree or edges");
        int maxDepth = Math.max(1, a.integer("max_depth"));
        int maxNodes = Math.max(1, a.integer("max_nodes"));
        return McpSupport.onSwing(() -> {
            StringBuilder sb = new StringBuilder();
            if (dir.equals("callees") || dir.equals("both")) {
                sb.append(graph(root, true, maxDepth, maxNodes, format));
            }
            if (dir.equals("both")) sb.append("\n\n");
            if (dir.equals("callers") || dir.equals("both")) {
                sb.append(graph(root, false, maxDepth, maxNodes, format));
            }
            return sb.toString();
        });
    }

    private String graph(Function root, boolean down, int maxDepth, int maxNodes, String format) {
        StringBuilder sb = new StringBuilder();
        sb.append(down ? "Callees" : "Callers").append(" graph of ").append(McpSupport.fqn(root))
            .append(" (max_depth ").append(maxDepth).append(")\n");
        Set<Function> visited = new LinkedHashSet<>();
        visited.add(root);
        boolean[] truncated = { false };
        if (format.equals("tree")) {
            sb.append(McpSupport.fqn(root)).append(" @ ").append(root.getEntryPoint()).append('\n');
            tree(root, down, 1, maxDepth, maxNodes, visited, sb, truncated);
        }
        else {
            Deque<Object[]> queue = new ArrayDeque<>();
            queue.add(new Object[] { root, 0 });
            int edges = 0;
            while (!queue.isEmpty()) {
                Object[] item = queue.poll();
                Function f = (Function) item[0];
                int depth = (Integer) item[1];
                if (depth >= maxDepth) continue;
                Map<Function, List<Address>> next = down ? calleeSites(f) : callerSites(f);
                for (Map.Entry<Function, List<Address>> e : next.entrySet()) {
                    Function from = down ? f : e.getKey();
                    Function to = down ? e.getKey() : f;
                    sb.append(McpSupport.fqn(from)).append(" -> ").append(McpSupport.fqn(to)).append(" @ ")
                        .append(sites(e.getValue())).append('\n');
                    edges++;
                    if (visited.add(e.getKey())) {
                        if (visited.size() > maxNodes) {
                            truncated[0] = true;
                            break;
                        }
                        queue.add(new Object[] { e.getKey(), depth + 1 });
                    }
                }
                if (truncated[0]) break;
            }
            sb.append("(").append(visited.size()).append(" functions, ").append(edges).append(" edges)");
        }
        if (truncated[0]) sb.append("\n-- truncated at max_nodes ").append(maxNodes).append(" --");
        return sb.toString().trim();
    }

    private void tree(Function f, boolean down, int depth, int maxDepth, int maxNodes, Set<Function> visited,
            StringBuilder sb, boolean[] truncated) {
        if (depth > maxDepth || truncated[0]) return;
        Map<Function, List<Address>> next = down ? calleeSites(f) : callerSites(f);
        for (Map.Entry<Function, List<Address>> e : next.entrySet()) {
            Function g = e.getKey();
            boolean seen = visited.contains(g);
            sb.append("  ".repeat(depth)).append(McpSupport.fqn(g)).append(" @ ").append(g.getEntryPoint())
                .append(g.isExternal() ? " [external]" : g.isThunk() ? " [thunk]" : "")
                .append(seen ? " (seen)" : "").append('\n');
            if (seen) continue;
            visited.add(g);
            if (visited.size() >= maxNodes) {
                truncated[0] = true;
                return;
            }
            tree(g, down, depth + 1, maxDepth, maxNodes, visited, sb, truncated);
        }
    }

    // ------------------------------------------------------------------
    // Data flow
    // ------------------------------------------------------------------

    private String dataFlow(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        String dir = a.str("direction").trim().toLowerCase(Locale.ROOT);
        if (!dir.equals("forward") && !dir.equals("backward")) {
            throw McpSupport.fail("direction must be forward or backward");
        }
        boolean forward = dir.equals("forward");
        String variable = a.str("variable");
        String addressText = a.str("address");
        String registerName = a.str("register");
        if (variable.isEmpty() && addressText.isEmpty()) {
            throw McpSupport.fail("Pass variable (decompiler variable name) or address");
        }
        Function f = McpSupport.function(p, a.str("function_name").isEmpty() ? null : a.str("function_name"),
            a.str("function_name").isEmpty() ? addressText : null);
        DecompileResults r = decompiler.decompile(f, 60);
        HighFunction hf = r.getHighFunction();
        if (hf == null) throw McpSupport.fail("No decompiler data for " + McpSupport.fqn(f));

        List<Varnode> starts = new ArrayList<>();
        String startDesc;
        if (!variable.isEmpty()) {
            HighSymbol hs = null;
            java.util.Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (s.getName().equals(variable)) hs = s;
            }
            if (hs == null) {
                java.util.Iterator<HighSymbol> g = hf.getGlobalSymbolMap().getSymbols();
                while (g.hasNext()) {
                    HighSymbol s = g.next();
                    if (s.getName().equals(variable)) hs = s;
                }
            }
            if (hs == null || hs.getHighVariable() == null) {
                throw McpSupport.fail("Decompiler variable " + variable + " not found in " + McpSupport.fqn(f));
            }
            HighVariable hv = hs.getHighVariable();
            for (Varnode v : hv.getInstances()) starts.add(v);
            startDesc = "variable " + variable;
        }
        else {
            Address at = McpSupport.address(p, addressText);
            Register reg = null;
            if (!registerName.isEmpty()) {
                reg = p.getRegister(registerName);
                if (reg == null) throw McpSupport.fail("Unknown register " + registerName);
            }
            java.util.Iterator<PcodeOpAST> ops = hf.getPcodeOps(at);
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                List<Varnode> candidates = new ArrayList<>();
                if (forward) {
                    if (op.getOutput() != null) candidates.add(op.getOutput());
                    if (reg != null) for (Varnode in : op.getInputs()) candidates.add(in);
                }
                else {
                    for (Varnode in : op.getInputs()) candidates.add(in);
                    if (reg != null && op.getOutput() != null) candidates.add(op.getOutput());
                }
                for (Varnode v : candidates) {
                    if (v == null || v.isConstant() && reg == null) continue;
                    if (reg != null && !(v.isRegister() && matchesRegister(p, v, reg))) continue;
                    if (!starts.contains(v)) starts.add(v);
                }
            }
            if (starts.isEmpty()) {
                throw McpSupport.fail("No " + (reg == null ? "" : reg.getName() + " ") + "value found in the "
                    + "decompiler P-code at " + at + " (the instruction may have been simplified away; "
                    + "try a neighbouring address or a variable name)");
            }
            startDesc = (reg == null ? "values" : reg.getName()) + " at " + at;
        }

        Set<PcodeOp> slice = new LinkedHashSet<>();
        for (Varnode v : starts) {
            slice.addAll(forward ? DecompilerUtils.getForwardSliceToPCodeOps(v)
                : DecompilerUtils.getBackwardSliceToPCodeOps(v));
        }
        List<PcodeOp> ordered = new ArrayList<>(slice);
        ordered.sort(Comparator.comparing((PcodeOp op) -> op.getSeqnum().getTarget())
            .thenComparingInt(op -> op.getSeqnum().getTime()));
        int maxSteps = Math.max(1, a.integer("max_steps"));
        Listing listing = p.getListing();
        Map<Address, String> instrText = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        sb.append(forward ? "Forward" : "Backward").append(" data flow of ").append(startDesc).append(" in ")
            .append(McpSupport.fqn(f)).append(" (").append(ordered.size()).append(" P-code ops)\n");
        int n = 0;
        for (PcodeOp op : ordered) {
            if (n++ >= maxSteps) {
                sb.append("-- truncated at max_steps ").append(maxSteps).append(" --");
                break;
            }
            Address ia = op.getSeqnum().getTarget();
            String it = instrText.computeIfAbsent(ia, k -> {
                Instruction ins = McpSupport.onSwing(() -> listing.getInstructionAt(k));
                return ins == null ? "" : ins.toString();
            });
            sb.append(ia).append(": ").append(String.format("%-28s", it)).append(" | ").append(op).append('\n');
        }
        return sb.toString().trim();
    }

    private static boolean matchesRegister(Program p, Varnode v, Register reg) {
        Register vr = p.getRegister(v.getAddress(), v.getSize());
        if (vr == null) vr = p.getRegister(v.getAddress());
        if (vr == null) return false;
        return vr.equals(reg) || vr.getBaseRegister().equals(reg.getBaseRegister());
    }

    // ------------------------------------------------------------------
    // Scalars
    // ------------------------------------------------------------------

    static long parseValue(String text) {
        if (text == null || text.isBlank()) throw McpSupport.fail("value is required");
        String t = text.trim().replace("_", "");
        boolean neg = t.startsWith("-");
        if (neg) t = t.substring(1);
        try {
            long v = t.startsWith("0x") || t.startsWith("0X") ? Long.parseUnsignedLong(t.substring(2), 16)
                : Long.parseLong(t);
            return neg ? -v : v;
        }
        catch (NumberFormatException e) {
            throw McpSupport.fail("Invalid value: " + text);
        }
    }

    private String searchScalars(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        long value = parseValue(a.str("value"));
        String inFn = a.str("in_function").toLowerCase(Locale.ROOT);
        String toFn = a.str("to_function").toLowerCase(Locale.ROOT);
        long deadline = System.currentTimeMillis() + Math.max(1, a.integer("time_budget_seconds")) * 1000L;
        return McpSupport.onSwing(() -> {
            List<String> lines = new ArrayList<>();
            boolean truncated = false;
            Listing listing = p.getListing();
            List<InstructionIterator> sources = new ArrayList<>();
            if (!inFn.isEmpty()) {
                for (Function f : p.getFunctionManager().getFunctions(true)) {
                    if (McpSupport.fqn(f).toLowerCase(Locale.ROOT).contains(inFn)) {
                        sources.add(listing.getInstructions(f.getBody(), true));
                    }
                }
            }
            else {
                sources.add(listing.getInstructions(true));
            }
            outer:
            for (InstructionIterator it : sources) {
                while (it.hasNext()) {
                    if (System.currentTimeMillis() > deadline) {
                        truncated = true;
                        break outer;
                    }
                    Instruction ins = it.next();
                    for (int op = 0; op < ins.getNumOperands(); op++) {
                        Scalar match = null;
                        for (Object o : ins.getOpObjects(op)) {
                            if (o instanceof Scalar && scalarEquals((Scalar) o, value)) match = (Scalar) o;
                        }
                        if (match == null) continue;
                        String callee = "";
                        if (!toFn.isEmpty()) {
                            callee = followingCall(p, ins, toFn);
                            if (callee == null) continue;
                        }
                        Function f = p.getFunctionManager().getFunctionContaining(ins.getAddress());
                        lines.add(ins.getAddress() + ": " + ins + "  [operand " + op + "]"
                            + (f == null ? "" : " in " + McpSupport.fqn(f))
                            + (callee.isEmpty() ? "" : " -> " + callee));
                        break;
                    }
                }
            }
            String out = McpSupport.page(lines, a.integer("offset"), a.integer("limit"));
            if (truncated) out += "\n-- scan stopped after the time budget; results are partial "
                + "(narrow with in_function or increase time_budget_seconds) --";
            return out;
        });
    }

    private static boolean scalarEquals(Scalar s, long value) {
        if (s.getValue() == value || s.getUnsignedValue() == value) return true;
        int bits = s.bitLength();
        if (bits > 0 && bits < 64) {
            long mask = (1L << bits) - 1;
            return (s.getUnsignedValue() & mask) == (value & mask) && (value < 0 || value <= mask);
        }
        return false;
    }

    /**
     * The first call within 10 instructions after {@code start}; returns its
     * description when the callee's name contains {@code text}, else null.
     */
    private static String followingCall(Program p, Instruction start, String text) {
        Instruction ins = start;
        for (int i = 0; i <= 10 && ins != null; i++) {
            for (Reference r : ins.getReferencesFrom()) {
                if (!r.getReferenceType().isCall()) continue;
                Function callee = p.getFunctionManager().getFunctionAt(r.getToAddress());
                String name = callee == null ? r.getToAddress().toString() : McpSupport.fqn(callee);
                return name.toLowerCase(Locale.ROOT).contains(text) ? name + " at " + ins.getAddress() : null;
            }
            ins = ins.getNext();
        }
        return null;
    }
}
