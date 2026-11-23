package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.services.CodeViewerService;
import ghidra.program.util.ProgramLocation;

import java.util.*;

/** Listings and lookups: functions, classes, namespaces, imports/exports, segments, data, strings, current location. Part of the original GhidraMCP tool set. */
final class ListingTools extends CoreTool {

    ListingTools(McpEnvironment env, DecompilerService decompiler) {
        super(env, decompiler);
    }

    @Override
    void registerMcp(McpServer mcp) {
        mcp.tool("list_open_programs",
                "List all programs open in Ghidra — in any CodeBrowser window or opened by the server "
                    + "in the background. Each line is \"name<TAB>path<TAB>[window or background]"
                    + "[<TAB>(current)][<TAB>(unsaved changes)]\". Use a name or path as the `program` "
                    + "argument of other tools to target a specific binary.")
            .handler(a -> listOpenPrograms());

        mcp.tool("get_current_program",
                "Get the name and path of the currently focused program in Ghidra.")
            .handler(a -> describeCurrentProgram());

        mcp.tool("get_current_address", "Get the address currently selected by the user.")
            .handler(a -> getCurrentAddress());

        mcp.tool("get_current_function", "Get the function currently selected by the user.")
            .handler(a -> getCurrentFunction());

        mcp.tool("list_imports", "List imported symbols in the program with pagination.")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of results")
            .program()
            .handler(a -> listImports(a.str("program"), a.integer("offset"), a.integer("limit")));

        mcp.tool("list_exports", "List exported functions/symbols with pagination.")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of results")
            .program()
            .handler(a -> listExports(a.str("program"), a.integer("offset"), a.integer("limit")));

        mcp.tool("list_namespaces", "List all non-global namespaces in the program with pagination.")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of results")
            .program()
            .handler(a -> listNamespaces(a.str("program"), a.integer("offset"), a.integer("limit")));

    }

    // ----------------------------------------------------------------------------------
    // Text reports shared by the HTTP API and the MCP endpoint
    // ----------------------------------------------------------------------------------

    String describeCurrentProgram() {
        Program program = getCurrentProgram();
        return program != null
            ? program.getName() + "\t" + program.getDomainFile().getPathname()
            : "No program loaded";
    }

    String listImports(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    String listExports(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    String listNamespaces(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    String getCurrentAddress() {
        CodeViewerService service = env.activeCodeViewer();
        if (service == null) return "No CodeBrowser window is open";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    String getCurrentFunction() {
        CodeViewerService service = env.activeCodeViewer();
        if (service == null) return "No CodeBrowser window is open";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = location.getProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List every program currently open in the tool, marking the focused one.
     * Each line is "name\tpath[\t(current)]".
     */
    String listOpenPrograms() {
        List<McpEnvironment.OpenProgram> programs = env.openPrograms();
        if (programs.isEmpty()) return "No programs open";
        List<String> lines = new ArrayList<>();
        for (McpEnvironment.OpenProgram op : programs) {
            String marker = op.current ? "\t(current)" : "";
            String dirty = op.program.isChanged() ? "\t(unsaved changes)" : "";
            lines.add(String.format("%s\t%s\t[%s]%s%s",
                op.program.getName(), op.program.getDomainFile().getPathname(), op.location(),
                marker, dirty));
        }
        return String.join("\n", lines);
    }
}
