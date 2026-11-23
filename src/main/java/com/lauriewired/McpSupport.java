package com.lauriewired;

import java.awt.GraphicsEnvironment;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.SwingUtilities;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

/** Helpers shared by the MCP tool groups. */
final class McpSupport {

    private McpSupport() {
    }

    /** Reports a caller error; surfaced to the client as a tool error with this message. */
    static McpServer.InvalidArgumentException fail(String message) {
        return new McpServer.InvalidArgumentException(message);
    }

    // ------------------------------------------------------------------
    // Programs and addresses
    // ------------------------------------------------------------------

    /** Resolves the optional {@code program} selector or fails with the list of open programs. */
    static Program program(McpEnvironment env, String selector) {
        Program p;
        try {
            p = env.resolveProgram(selector);
        }
        catch (McpEnvironment.ProgramResolutionException e) {
            throw fail(e.getMessage());
        }
        if (p != null) return p;
        List<McpEnvironment.OpenProgram> open = env.openPrograms();
        if (open.isEmpty()) {
            throw fail("No program is open. Use open_program (or list_project_files) first.");
        }
        StringBuilder sb = new StringBuilder();
        if (selector == null || selector.isBlank()) {
            sb.append("No current program; pass 'program'. Open programs:");
        }
        else {
            sb.append("Program not found: ").append(selector).append(". Open programs:");
        }
        for (McpEnvironment.OpenProgram op : open) {
            sb.append("\n  ").append(op.program.getDomainFile().getPathname());
        }
        throw fail(sb.toString());
    }

    static Address address(Program program, String text) {
        if (text == null || text.isBlank()) throw fail("Address is required");
        String s = text.trim();
        Address a = program.getAddressFactory().getAddress(s);
        if (a == null && (s.startsWith("0x") || s.startsWith("0X"))) {
            a = program.getAddressFactory().getAddress(s.substring(2));
        }
        if (a == null) throw fail("Invalid address: " + text);
        return a;
    }

    // ------------------------------------------------------------------
    // Functions
    // ------------------------------------------------------------------

    /**
     * Finds a function by address (entry point or containing address) or by
     * name. Names may be fully qualified ({@code A::B::f}); a bare name matches
     * any namespace when unique, otherwise the global one, else it is ambiguous.
     */
    static Function function(Program program, String name, String address) {
        if (address != null && !address.isBlank()) {
            Address a = address(program, address);
            Function f = program.getFunctionManager().getFunctionAt(a);
            if (f == null) f = program.getFunctionManager().getFunctionContaining(a);
            if (f == null) throw fail("No function at or containing " + a);
            return f;
        }
        if (name == null || name.isBlank()) throw fail("Pass a function name or address");
        String n = name.trim();
        if (n.startsWith("::")) n = n.substring(2);
        List<Function> exact = new ArrayList<>();
        List<Function> bare = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (fqn(f).equals(n)) exact.add(f);
            else if (!n.contains("::") && f.getName().equals(n)) bare.add(f);
        }
        if (exact.size() == 1) return exact.get(0);
        if (exact.isEmpty() && bare.size() == 1) return bare.get(0);
        List<Function> candidates = exact.isEmpty() ? bare : exact;
        if (candidates.isEmpty()) {
            Function byDefault = defaultNamed(program, n);
            if (byDefault != null) return byDefault;
            throw fail("Function not found: " + name);
        }
        StringBuilder sb = new StringBuilder("Function name '" + name + "' is ambiguous:");
        for (Function f : candidates) {
            sb.append("\n  ").append(fqn(f)).append(" @ ").append(f.getEntryPoint());
        }
        sb.append("\nUse the fully qualified name or the address.");
        throw fail(sb.toString());
    }

    /** Resolves default names like FUN_00401000 / thunk_FUN_... by their address suffix. */
    private static Function defaultNamed(Program program, String name) {
        int idx = name.lastIndexOf('_');
        if (idx < 0) return null;
        Address a = program.getAddressFactory().getAddress(name.substring(idx + 1));
        if (a == null) return null;
        Function f = program.getFunctionManager().getFunctionAt(a);
        return f != null && f.getName().equals(name) ? f : null;
    }

    // ------------------------------------------------------------------
    // Data types and qualified names
    // ------------------------------------------------------------------

    /** Parses a type expression such as {@code int}, {@code char *}, {@code Node[4]} or a category path. */
    static ghidra.program.model.data.DataType dataType(Program program, String text) {
        if (text == null || text.isBlank()) throw fail("Data type is required");
        ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();
        String t = text.trim();
        if (t.startsWith("/")) {
            ghidra.program.model.data.DataType byPath = dtm.getDataType(t);
            if (byPath != null) return byPath;
        }
        ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(dtm, dtm, null,
            ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);
        try {
            ghidra.program.model.data.DataType dt = parser.parse(t);
            if (dt == null) throw fail("Unknown data type: " + text);
            return dt;
        }
        catch (ghidra.program.model.data.InvalidDataTypeException
                | ghidra.util.exception.CancelledException e) {
            throw fail("Invalid data type '" + text + "': " + e.getMessage());
        }
    }

    /**
     * Renames {@code symbol}. {@code A::B::name} moves it into namespace A::B
     * (created if missing); a leading {@code ::} moves it to the global
     * namespace; a bare name keeps the current namespace. Call in a transaction.
     */
    static void applyName(Program program, Symbol symbol, String newName) throws Exception {
        if (newName == null || newName.isBlank()) throw fail("New name is required");
        String n = newName.trim();
        ghidra.program.model.symbol.SourceType src = ghidra.program.model.symbol.SourceType.USER_DEFINED;
        if (n.startsWith("::")) {
            symbol.setNameAndNamespace(n.substring(2), program.getGlobalNamespace(), src);
            return;
        }
        int idx = n.lastIndexOf("::");
        if (idx < 0) {
            symbol.setName(n, src);
            return;
        }
        String nsPath = n.substring(0, idx);
        String name = n.substring(idx + 2);
        if (nsPath.startsWith("Global::")) nsPath = nsPath.substring("Global::".length());
        Namespace ns = ghidra.app.util.NamespaceUtils.createNamespaceHierarchy(nsPath,
            program.getGlobalNamespace(), program, src);
        symbol.setNameAndNamespace(name, ns, src);
    }

    // ------------------------------------------------------------------
    // Names
    // ------------------------------------------------------------------

    /** Fully qualified name without the global namespace prefix, e.g. {@code A::B::f}. */
    static String fqn(Symbol symbol) {
        return symbol == null ? "" : symbol.getName(true);
    }

    static String fqn(Function f) {
        return f == null ? "" : f.getSymbol().getName(true);
    }

    static String namespacePath(Namespace ns) {
        return ns == null || ns.isGlobal() ? "" : ns.getName(true);
    }

    static Pattern regex(String text) {
        if (text == null || text.isEmpty()) return null;
        try {
            return Pattern.compile(text);
        }
        catch (PatternSyntaxException e) {
            throw fail("Invalid regular expression: " + e.getDescription());
        }
    }

    // ------------------------------------------------------------------
    // Threading and transactions
    // ------------------------------------------------------------------

    /**
     * Runs {@code work} on the Swing thread (directly when headless or already
     * on it). Database iterators are not safe against concurrent analysis
     * otherwise. RuntimeExceptions propagate unchanged.
     */
    static <T> T onSwing(Callable<T> work) {
        if (GraphicsEnvironment.isHeadless() || SwingUtilities.isEventDispatchThread()) {
            return call(work);
        }
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> error = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    result.set(work.call());
                }
                catch (Throwable t) {
                    error.set(t);
                }
            });
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for the Swing thread");
        }
        catch (InvocationTargetException e) {
            error.set(e.getCause());
        }
        Throwable t = error.get();
        if (t instanceof RuntimeException) throw (RuntimeException) t;
        if (t instanceof Error) throw (Error) t;
        if (t != null) throw new IllegalStateException(t.getMessage(), t);
        return result.get();
    }

    private static <T> T call(Callable<T> work) {
        try {
            return work.call();
        }
        catch (RuntimeException e) {
            throw e;
        }
        catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /** Runs {@code work} in a transaction on the Swing thread; rolls back on any exception. */
    static <T> T write(Program program, String description, Callable<T> work) {
        return onSwing(() -> {
            int tx = program.startTransaction(description);
            boolean commit = false;
            try {
                T value = work.call();
                commit = true;
                return value;
            }
            finally {
                program.endTransaction(tx, commit);
            }
        });
    }

    // ------------------------------------------------------------------
    // Formatting
    // ------------------------------------------------------------------

    /** Applies offset/limit and appends a footer describing the page when truncated. */
    static String page(List<String> lines, int offset, int limit) {
        int total = lines.size();
        int start = Math.max(0, offset);
        int end = limit <= 0 ? total : (int) Math.min(total, (long) start + limit);
        if (start >= total) {
            return total == 0 ? "(none)" : "(no items at offset " + offset + "; total " + total + ")";
        }
        List<String> sub = new ArrayList<>(lines.subList(start, end));
        if (start > 0 || end < total) {
            sub.add("-- " + (start + 1) + "-" + end + " of " + total
                + (end < total ? "; next offset " + end : "") + " --");
        }
        return String.join("\n", sub);
    }

    static String hex(long value) {
        return value < 0 ? "-0x" + Long.toHexString(-value) : "0x" + Long.toHexString(value);
    }
}
