package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import java.util.*;

/**
 * Base of the domain classes that implement the original GhidraMCP tools:
 * shared program, address and data type helpers.
 */
abstract class CoreTool {

    final McpEnvironment env;
    final DecompilerService decompiler;

    CoreTool(McpEnvironment env, DecompilerService decompiler) {
        this.env = env;
        this.decompiler = decompiler;
    }

    /** Registers this domain's MCP tools. */
    void registerMcp(McpServer mcp) {
    }

    static String emptyToNull(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    static String joinStrings(JsonArray values, String separator) {
        List<String> parts = new ArrayList<>();
        for (JsonElement value : values) {
            parts.add(value.getAsString());
        }
        return String.join(separator, parts);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Applies a command synchronously in its own transaction. Unlike
     * PluginTool.execute this works without a tool (project window, headless).
     */
    @SuppressWarnings("unchecked")
    static boolean executeCommand(ghidra.framework.cmd.Command<Program> cmd, Program program) {
        int tx = program.startTransaction(cmd.getName());
        boolean ok = false;
        try {
            if (cmd instanceof ghidra.framework.cmd.BackgroundCommand) {
                ok = ((ghidra.framework.cmd.BackgroundCommand<Program>) cmd)
                    .applyTo(program, TaskMonitor.DUMMY);
            }
            else {
                ok = cmd.applyTo(program);
            }
            return ok;
        }
        finally {
            program.endTransaction(tx, ok);
        }
    }

    /**
     * Undefined bytes are exposed by Ghidra as {@link Data} code units too.  Only
     * explicitly defined data should prevent the disassembler from replacing a
     * code unit.
     */
    static boolean isDefinedData(CodeUnit codeUnit) {
        return codeUnit instanceof Data && ((Data) codeUnit).isDefined();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (dtm == null || typeName == null || typeName.trim().isEmpty()) {
            return null;
        }

        String requested = typeName.trim();

        // An explicit category path is unambiguous and should win over a name search.
        if (requested.startsWith("/")) {
            DataType byPath = dtm.getDataType(requested);
            if (byPath != null) return byPath;
        }

        // Preserve exact user-defined names before interpreting C decorations.
        DataType dataType = findDataTypeByNameInAllCategories(dtm, requested);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (requested.startsWith("P") && requested.length() > 1 &&
                requested.indexOf(' ') < 0 && requested.indexOf('*') < 0) {
            String baseTypeName = requested.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                DataType voidType = dtm.getDataType("/void");
                return voidType == null ? null : dtm.getPointer(voidType);
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }

        // Normalize convenience aliases, then let Ghidra parse C pointer/array
        // decorations (for example "MyStruct *" or "char[32]").
        String normalized;
        switch (requested.toLowerCase(Locale.ROOT)) {
            case "uint":
            case "unsigned int":
            case "dword":
                normalized = "uint";
                break;
            case "ushort":
            case "unsigned short":
            case "word":
                normalized = "ushort";
                break;
            case "byte":
                normalized = "byte";
                break;
            case "uchar":
            case "unsigned char":
                normalized = "uchar";
                break;
            case "longlong":
            case "__int64":
                normalized = "longlong";
                break;
            case "ulonglong":
            case "unsigned __int64":
                normalized = "ulonglong";
                break;
            case "qword":
                normalized = "qword";
                break;
            case "pointer":
                normalized = "void *";
                break;
            case "bool":
            case "boolean":
                normalized = "bool";
                break;
            default:
                normalized = requested;
                break;
        }

        try {
            DataTypeParser parser = new DataTypeParser(
                dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL);
            return parser.parse(normalized);
        } catch (Exception e) {
            Msg.warn(this, "Could not resolve data type '" + requested + "': " + e.getMessage());
            return null;
        }
    }

    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        if (dtm == null || typeName == null || typeName.isEmpty()) return null;
        if (typeName.startsWith("/")) return dtm.getDataType(typeName);

        List<DataType> exactMatches = new ArrayList<>();
        List<DataType> caseInsensitiveMatches = new ArrayList<>();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(typeName)) exactMatches.add(dt);
            else if (dt.getName().equalsIgnoreCase(typeName)) caseInsensitiveMatches.add(dt);
        }

        List<DataType> matches = exactMatches.isEmpty() ? caseInsensitiveMatches : exactMatches;
        if (matches.size() == 1) return matches.get(0);
        for (DataType match : matches) {
            if (match.getCategoryPath().isRoot()) return match;
        }
        if (matches.size() > 1) {
            Msg.warn(this, "Ambiguous data type name '" + typeName +
                "'; use a fully-qualified category path");
        }
        return null;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = (int) Math.min(items.size(), (long) start + Math.max(0, limit));

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    public Program getCurrentProgram() {
        return env.currentProgram();
    }

    /**
     * Resolve a program by name, domain-file name or project path among all
     * open programs (every tool plus background programs). Null/empty selects
     * the current program.
     */
    Program getProgramByName(String programName) {
        return env.resolveProgram(programName);
    }
}
