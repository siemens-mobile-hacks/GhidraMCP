package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.CategoryPath;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.util.cparser.C.CParser;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String HOST_OPTION_NAME = "Server Host";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String DEFAULT_HOST = "127.0.0.1";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(HOST_OPTION_NAME, DEFAULT_HOST,
            null,
            "The network interface address for the embedded HTTP server. " +
            "Use 127.0.0.1 for local-only access. Requires plugin reload to take effect.");
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        String configuredHost = options.getString(HOST_OPTION_NAME, DEFAULT_HOST).trim();
        final String host = configuredHost.isEmpty() ? DEFAULT_HOST : configuredHost;
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(host, port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(qparams.get("program"), offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(qparams.get("program"), offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(qparams.get("program"), name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("program"), params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameDataAtAddress(
                params.get("program"), params.get("address"), params.get("newName")));
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(params.get("program"), functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(qparams.get("program"), offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(qparams.get("program"), offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(qparams.get("program"), offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(qparams.get("program"), offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(qparams.get("program"), offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(qparams.get("program"), searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(qparams.get("program"), address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_open_programs", exchange -> {
            sendResponse(exchange, listOpenPrograms());
        });

        server.createContext("/get_current_program", exchange -> {
            Program program = getCurrentProgram();
            sendResponse(exchange, program != null
                ? program.getName() + "\t" + program.getDomainFile().getPathname()
                : "No program loaded");
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 1000);
            sendResponse(exchange, listFunctions(qparams.get("program"), offset, limit));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(qparams.get("program"), address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(qparams.get("program"), address));
        });

        server.createContext("/disassemble_code", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = disassembleCode(params.get("program"), params.get("address"), params.get("mode"));
            sendResponse(exchange, result);
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(params.get("program"), address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(params.get("program"), address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(params.get("program"), functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");
            String callingConvention = params.get("calling_convention");
            String sourceType = params.get("source_type");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(params.get("program"), functionAddress,
                prototype, callingConvention, sourceType);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getProgramByName(params.get("program"));
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType resolvedType = resolveDataType(dtm, newType);
                if (resolvedType != null) {
                    responseMsg.append("Resolved type: ").append(resolvedType.getDisplayName())
                        .append(" from ").append(resolvedType.getPathName()).append("\n");
                } else {
                    responseMsg.append("Type could not be resolved: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(program, functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(qparams.get("program"), address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(qparams.get("program"), address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(qparams.get("program"), name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(qparams.get("program"), offset, limit, filter));
        });

        server.createContext("/clear_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String size = params.get("size");
            String result = clearData(params.get("program"), address, size);
            sendResponse(exchange, result);
        });

        server.createContext("/define_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String dataType = params.get("data_type");
            String label = params.get("label");
            String result = defineData(params.get("program"), address, dataType, label);
            sendResponse(exchange, result);
        });

        server.createContext("/define_data_batch", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String body = readRequestBody(exchange);
            String result = defineDataBatch(qparams.get("program"), body);
            sendResponse(exchange, result);
        });

        server.createContext("/read_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String length = qparams.get("length");
            String result = readBytes(qparams.get("program"), address, length);
            sendResponse(exchange, result);
        });

        server.createContext("/get_data_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String result = getDataAt(qparams.get("program"), address);
            sendResponse(exchange, result);
        });

        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDataTypes(qparams.get("program"), qparams.get("query"),
                qparams.get("category"), offset, limit));
        });

        server.createContext("/get_data_type", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getDataTypeDescription(qparams.get("program"), qparams.get("name")));
        });

        server.createContext("/batch_rename_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String body = readRequestBody(exchange);
            String result = batchRenameFunctions(qparams.get("program"), body);
            sendResponse(exchange, result);
        });

        server.createContext("/batch_set_comments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String body = readRequestBody(exchange);
            String result = batchSetComments(qparams.get("program"), body);
            sendResponse(exchange, result);
        });

        server.createContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String namespace = params.get("namespace");
            String result = createLabel(params.get("program"), address, name, namespace);
            sendResponse(exchange, result);
        });

        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = createFunction(params.get("program"), address, name);
            sendResponse(exchange, result);
        });

        server.createContext("/create_enum", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String body = readRequestBody(exchange);
            String result = createEnum(qparams.get("program"), body);
            sendResponse(exchange, result);
        });

        server.createContext("/create_struct", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String body = readRequestBody(exchange);
            String result = createStruct(qparams.get("program"), body);
            sendResponse(exchange, result);
        });

        server.createContext("/create_union", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String result = createUnion(qparams.get("program"), readRequestBody(exchange));
            sendResponse(exchange, result);
        });

        server.createContext("/create_typedef", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String result = createTypedef(qparams.get("program"), readRequestBody(exchange));
            sendResponse(exchange, result);
        });

        server.createContext("/parse_c_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String result = parseCTypes(qparams.get("program"), readRequestBody(exchange));
            sendResponse(exchange, result);
        });

        server.createContext("/apply_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = applyDataType(params.get("program"), params.get("address"),
                params.get("data_type"), parseBooleanOrDefault(params.get("clear_existing"), true),
                params.get("label"));
            sendResponse(exchange, result);
        });

        server.createContext("/apply_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String structName = params.get("struct_name");
            String result = applyStruct(params.get("program"), address, structName);
            sendResponse(exchange, result);
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on " + host + ":" + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on " + host + ":" + port +
                    ". Address or port might be unavailable.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(String programName, int offset, int limit) {
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

    private String listNamespaces(String programName, int offset, int limit) {
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

    private String listDefinedData(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String programName, String searchTerm, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String programName, String name) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String programName, String oldName, String newName) {
        Program program = getProgramByName(programName);
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private String renameDataAtAddress(String programName, String addressStr, String newName) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "Address is required";
        if (newName == null || newName.isBlank()) return "New name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to rename data");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) throw new IllegalArgumentException("Invalid address: " + addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data == null) {
                        result.set("No data defined at " + addr);
                        return;
                    }
                    SymbolTable symTable = program.getSymbolTable();
                    Symbol symbol = symTable.getPrimarySymbol(addr);
                    if (symbol != null) {
                        symbol.setName(newName.trim(), SourceType.USER_DEFINED);
                    } else {
                        symTable.createLabel(addr, newName.trim(), SourceType.USER_DEFINED);
                    }
                    success = true;
                    result.set("Data renamed to '" + newName.trim() + "' at " + addr);
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                    result.set("Error renaming data: " + e.getMessage());
                }
                finally {
                    program.endTransaction(tx, success);
                }
            });
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Rename data interrupted";
        }
        catch (InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
            return "Error renaming data: " + e.getMessage();
        }
        return result.get();
    }

    private String renameVariableInFunction(String programName, String functionName, String oldVarName, String newVarName) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            String errorMsg = "Rename variable interrupted";
            Msg.error(this, errorMsg, e);
            return errorMsg;
        } catch (InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String programName, String addressStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions(String programName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        List<String> result = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.add(String.format("%s at %s", func.getName(), func.getEntryPoint()));
        }
        return paginateList(result, offset, limit);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String programName, String addressStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String programName, String addressStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                if (!func.getBody().contains(instr.getAddress())) continue;
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String programName, String addressStr, String comment, int commentType, String transactionName) {
        Program program = getProgramByName(programName);
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Disassembles undefined bytes, with explicit ARM/Thumb context support.
     */
    private String disassembleCode(String programName, String addressStr, String modeStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        String mode = modeStr == null || modeStr.isBlank()
            ? "auto" : modeStr.trim().toLowerCase(Locale.ROOT);
        if (!mode.equals("auto") && !mode.equals("arm") && !mode.equals("thumb")) {
            return "Invalid disassembly mode '" + modeStr + "'; expected auto, arm, or thumb";
        }

        Address requested;
        try {
            requested = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address '" + addressStr + "': " + e.getMessage();
        }
        if (requested == null) return "Invalid address: " + addressStr;

        Address start = requested;
        if (mode.equals("thumb")) {
            start = requested.getNewAddress(requested.getOffset() & ~1L);
        } else if (mode.equals("arm")) {
            start = requested.getNewAddress(requested.getOffset() & ~3L);
        }
        final Address disassemblyStart = start;

        if (!program.getMemory().contains(disassemblyStart)) {
            return "Address is not in program memory: " + disassemblyStart;
        }
        if ((mode.equals("arm") || mode.equals("thumb")) &&
                program.getProgramContext().getRegister("TMode") == null) {
            return "Program language " + program.getLanguageID() +
                " does not expose the ARM TMode context register";
        }

        AtomicReference<String> result = new AtomicReference<>("Failed to disassemble code");
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Disassemble code via HTTP");
                boolean success = false;
                try {
                    Listing listing = program.getListing();
                    Instruction existing = listing.getInstructionAt(disassemblyStart);
                    if (existing != null) {
                        result.set("Instruction already defined at " + disassemblyStart +
                            ": " + existing);
                        return;
                    }

                    CodeUnit codeUnit = listing.getCodeUnitContaining(disassemblyStart);
                    if (codeUnit instanceof Data) {
                        result.set("Cannot disassemble at " + disassemblyStart +
                            ": defined data overlaps the address; clear it first");
                        return;
                    }

                    DisassembleCommand cmd = mode.equals("auto")
                        ? new DisassembleCommand(disassemblyStart, null, true)
                        : new ArmDisassembleCommand(disassemblyStart, null, mode.equals("thumb"));
                    if (!cmd.applyTo(program, new ConsoleTaskMonitor())) {
                        String status = cmd.getStatusMsg();
                        result.set("Failed to disassemble at " + disassemblyStart +
                            (status == null || status.isEmpty() ? "" : ": " + status));
                        return;
                    }

                    Instruction created = listing.getInstructionAt(disassemblyStart);
                    if (created == null) {
                        result.set("Ghidra did not create an instruction at " + disassemblyStart);
                        return;
                    }

                    success = true;
                    result.set("Disassembled " + cmd.getDisassembledAddressSet().getNumAddresses() +
                        " byte(s) from " + disassemblyStart + " in " + mode +
                        " mode; first instruction: " + created);
                } catch (Exception e) {
                    Msg.error(this, "Error disassembling code", e);
                    result.set("Error disassembling code: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Disassembly interrupted";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "Error disassembling code: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }
        return result.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String programName, String addressStr, String comment) {
        return setCommentAtAddress(programName, addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String programName, String addressStr, String comment) {
        return setCommentAtAddress(programName, addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String programName, String functionAddrStr, String newName) {
        Program program = getProgramByName(programName);
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String programName, String functionAddrStr,
                                                 String prototype, String callingConvention,
                                                 String sourceTypeStr) {
        // Input validation
        Program program = getProgramByName(programName);
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final SourceType sourceType;
        try {
            sourceType = parseSourceType(sourceTypeStr);
        } catch (IllegalArgumentException e) {
            return new PrototypeResult(false, e.getMessage());
        }

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, callingConvention,
                    sourceType, success, errorMessage));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            String msg = "Set function prototype interrupted";
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } catch (InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       String callingConvention, SourceType sourceType,
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // FunctionSignatureParser may select the program's default convention when the
            // declaration does not spell one out.  Preserve the existing convention unless
            // the caller explicitly asks to change it.
            String effectiveCallingConvention = callingConvention;
            if (effectiveCallingConvention == null || effectiveCallingConvention.isBlank()) {
                effectiveCallingConvention = func.getCallingConventionName();
            }

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(
                program, addr, func.getSignature(), prototype, effectiveCallingConvention, sourceType,
                success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr,
                                              ghidra.program.model.listing.FunctionSignature originalSignature,
                                              String prototype,
                                              String callingConvention, SourceType sourceType,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig =
                parser.parse(originalSignature, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, sourceType);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                Function appliedFunction = program.getFunctionManager().getFunctionAt(addr);
                if (appliedFunction == null) {
                    throw new IllegalStateException("Function disappeared after applying signature");
                }
                if (callingConvention != null && !callingConvention.isBlank()) {
                    appliedFunction.setCallingConvention(
                        normalizeCallingConvention(callingConvention));
                }
                appliedFunction.setSignatureSource(sourceType);
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    private SourceType parseSourceType(String sourceTypeStr) {
        if (sourceTypeStr == null || sourceTypeStr.isBlank()) return SourceType.USER_DEFINED;
        String normalized = sourceTypeStr.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        if (normalized.equals("USER")) normalized = "USER_DEFINED";
        try {
            return SourceType.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid source_type '" + sourceTypeStr +
                "'; expected default, analysis, ai, imported, or user_defined");
        }
    }

    private String normalizeCallingConvention(String callingConvention) {
        String normalized = callingConvention.trim();
        if (normalized.equalsIgnoreCase("unknown")) {
            return Function.UNKNOWN_CALLING_CONVENTION_STRING;
        }
        if (normalized.equalsIgnoreCase("default")) {
            return Function.DEFAULT_CALLING_CONVENTION_STRING;
        }
        return normalized;
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(Program program, String functionAddrStr, String variableName, String newType) {
        // Input validation
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String programName, String addressStr, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String programName, String addressStr, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String programName, String functionName, int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(String programName, int offset, int limit, String filter) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
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
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
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

    private String clearData(String programName, String addressStr, String sizeStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to clear data");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear data");
                boolean success = false;
                try {
                    Address start = program.getAddressFactory().getAddress(addressStr);
                    if (start == null) throw new IllegalArgumentException("Invalid address: " + addressStr);
                    Listing listing = program.getListing();

                    Address end;
                    if (sizeStr != null && !sizeStr.isEmpty()) {
                        int size = Integer.parseInt(sizeStr);
                        if (size <= 0) throw new IllegalArgumentException("Size must be positive");
                        end = start.add(size - 1);
                    } else {
                        Data data = listing.getDataAt(start);
                        if (data == null) {
                            data = listing.getDataContaining(start);
                        }
                        if (data != null) {
                            start = data.getMinAddress();
                            end = data.getMaxAddress();
                        } else {
                            result.set("No data defined at " + start);
                            return;
                        }
                    }

                    InstructionIterator instructions = listing.getInstructions(start, true);
                    if (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        if (instruction.getAddress().compareTo(end) <= 0) {
                            throw new IllegalArgumentException("Instruction at " + instruction.getAddress() +
                                " overlaps the range; clear_data never removes code");
                        }
                    }

                    listing.clearCodeUnits(start, end, false);
                    success = true;
                    result.set("Cleared data from " + start + " to " + end);
                } catch (Exception e) {
                    Msg.error(this, "Error clearing data", e);
                    result.set("Error clearing data: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            result.set("Clear data interrupted");
            Msg.error(this, "Clear data interrupted", e);
        } catch (InvocationTargetException e) {
            Msg.error(this, "Failed to execute clear data on Swing thread", e);
            result.set("Error clearing data: " + e.getMessage());
        }

        return result.get();
    }

    private String defineData(String programName, String addressStr, String dataTypeName, String label) {
        return applyDataType(programName, addressStr, dataTypeName, false, label);
    }

    private String defineDataBatch(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to define data batch");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();
            if (items.isEmpty()) return "Data batch must not be empty";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Define data batch");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Listing listing = program.getListing();
                    SymbolTable symTable = program.getSymbolTable();

                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String typeName = item.get("data_type").getAsString();
                        String label = item.has("label") ? item.get("label").getAsString() : null;

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            if (address == null) throw new IllegalArgumentException("Invalid address");
                            DataType dt = resolveDataType(dtm, typeName);
                            if (dt == null) throw new IllegalArgumentException("Unknown data type: " + typeName);
                            if (dt.getLength() <= 0) {
                                throw new IllegalArgumentException("Data type has no fixed positive length: " + typeName);
                            }
                            listing.createData(address, dt);

                            if (label != null && !label.isEmpty()) {
                                symTable.createLabel(address, label, SourceType.USER_DEFINED);
                            }
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = failed == 0 && succeeded == items.size();
                    result.set((success ? "Committed. " : "Rolled back. ") +
                        "Total: " + items.size() + ", Applied: " + succeeded +
                        ", Failed: " + failed +
                        (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in define data batch", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String readBytes(String programName, String addressStr, String lengthStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (lengthStr == null || lengthStr.isEmpty()) return "Length is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            int length = Integer.parseInt(lengthStr);
            byte[] bytes = new byte[length];
            program.getMemory().getBytes(addr, bytes);

            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            return hex.toString();
        } catch (Exception e) {
            return "Error reading bytes: " + e.getMessage();
        }
    }

    private String getDataAt(String programName, String addressStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Listing listing = program.getListing();

            Data data = listing.getDataAt(addr);
            String matchType = "exact";
            if (data == null) {
                data = listing.getDataContaining(addr);
                matchType = "containing";
            }

            if (data == null) {
                return "No data defined at " + addressStr;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Address: ").append(data.getAddress()).append("\n");
            sb.append("Match: ").append(matchType).append("\n");
            sb.append("Type: ").append(data.getDataType().getName()).append("\n");
            sb.append("Size: ").append(data.getLength()).append(" bytes\n");
            sb.append("Value: ").append(data.getDefaultValueRepresentation()).append("\n");

            Symbol[] symbols = program.getSymbolTable().getSymbols(data.getAddress());
            if (symbols.length > 0) {
                sb.append("Label: ").append(symbols[0].getName()).append("\n");
            }

            if ("containing".equals(matchType)) {
                long offset = addr.subtract(data.getAddress());
                sb.append("Offset within item: ").append(offset).append("\n");
            }

            return sb.toString();
        } catch (Exception e) {
            return "Error getting data: " + e.getMessage();
        }
    }

    private String listDataTypes(String programName, String query, String category,
                                 int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        String queryLower = query == null ? "" : query.toLowerCase(Locale.ROOT);
        String categoryPrefix = category == null ? "" : category.trim();
        List<String> lines = new ArrayList<>();
        Iterator<DataType> iterator = program.getDataTypeManager().getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dt = iterator.next();
            String path = dt.getPathName();
            if (!queryLower.isEmpty() && !path.toLowerCase(Locale.ROOT).contains(queryLower)) continue;
            if (!categoryPrefix.isEmpty() && !path.startsWith(categoryPrefix)) continue;
            lines.add(path + "\t" + dataTypeKind(dt) + "\t" + dt.getLength());
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    private String getDataTypeDescription(String programName, String name) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (name == null || name.trim().isEmpty()) return "Data type name is required";

        DataType dt = resolveDataType(program.getDataTypeManager(), name);
        if (dt == null) return "Data type not found: " + name;

        StringBuilder result = new StringBuilder();
        result.append("Path: ").append(dt.getPathName()).append('\n');
        result.append("Kind: ").append(dataTypeKind(dt)).append('\n');
        result.append("Size: ").append(dt.getLength()).append(" bytes\n");

        if (dt instanceof Composite) {
            Composite composite = (Composite) dt;
            result.append("Alignment: ").append(composite.getAlignment()).append('\n');
            result.append("Packing: ").append(composite.getPackingType()).append('\n');
            result.append("Fields:\n");
            for (DataTypeComponent component : composite.getDefinedComponents()) {
                result.append("  +").append(component.getOffset()).append("  ")
                    .append(component.getDataType().getDisplayName()).append("  ")
                    .append(component.getFieldName() == null ? component.getDefaultFieldName()
                                                            : component.getFieldName())
                    .append("  [").append(component.getLength()).append(" bytes]");
                if (component.getComment() != null && !component.getComment().isEmpty()) {
                    result.append("  // ").append(component.getComment());
                }
                result.append('\n');
            }
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
            result.append("Values:\n");
            String[] names = enumType.getNames();
            Arrays.sort(names);
            for (String entryName : names) {
                result.append("  ").append(entryName).append(" = ")
                    .append(enumType.getValue(entryName)).append('\n');
            }
        } else if (dt instanceof TypeDef) {
            result.append("Base type: ").append(((TypeDef) dt).getBaseDataType().getPathName())
                .append('\n');
        }
        return result.toString();
    }

    private String dataTypeKind(DataType dt) {
        if (dt instanceof ghidra.program.model.data.Structure) return "struct";
        if (dt instanceof ghidra.program.model.data.Union) return "union";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof ghidra.program.model.data.Pointer) return "pointer";
        if (dt instanceof ghidra.program.model.data.Array) return "array";
        if (dt instanceof ghidra.program.model.data.FunctionDefinition) return "function";
        return dt.getClass().getSimpleName();
    }

    private String batchRenameFunctions(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch rename");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();
            if (items.isEmpty()) return "Rename batch must not be empty";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch rename functions");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String newName = item.get("new_name").getAsString();

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            Function func = getFunctionForAddress(program, address);
                            if (func == null) {
                                failed++;
                                errors.append(addr).append(": No function at address\n");
                                continue;
                            }
                            func.setName(newName, SourceType.USER_DEFINED);
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = failed == 0 && succeeded == items.size();
                    result.set((success ? "Committed. " : "Rolled back. ") +
                        "Total: " + items.size() + ", Applied: " + succeeded +
                        ", Failed: " + failed +
                        (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in batch rename", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String batchSetComments(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch set comments");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String commentTypeStr = body.has("comment_type") ? body.get("comment_type").getAsString() : "decompiler";
            int commentType = "disassembly".equalsIgnoreCase(commentTypeStr)
                    ? CodeUnit.EOL_COMMENT : CodeUnit.PRE_COMMENT;
            JsonArray comments = body.getAsJsonArray("comments");
            if (comments == null || comments.isEmpty()) return "Comments batch must not be empty";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch set comments");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    Listing listing = program.getListing();

                    for (JsonElement el : comments) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String comment = item.get("comment").getAsString();

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            listing.setComment(address, commentType, comment);
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = failed == 0 && succeeded == comments.size();
                    result.set((success ? "Committed. " : "Rolled back. ") +
                        "Total: " + comments.size() + ", Applied: " + succeeded +
                        ", Failed: " + failed +
                        (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in batch set comments", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String createLabel(String programName, String addressStr, String name, String namespace) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (name == null || name.isEmpty()) return "Name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create label");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create label");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    SymbolTable symTable = program.getSymbolTable();

                    Namespace ns = null;
                    if (namespace != null && !namespace.isEmpty()) {
                        ns = symTable.getNamespace(namespace, null);
                        if (ns == null) {
                            ns = symTable.createNameSpace(null, namespace, SourceType.USER_DEFINED);
                        }
                    }

                    if (ns != null) {
                        symTable.createLabel(addr, name, ns, SourceType.USER_DEFINED);
                    } else {
                        symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                    }

                    success = true;
                    result.set("Label '" + name + "' created at " + addr);
                } catch (Exception e) {
                    Msg.error(this, "Error creating label", e);
                    result.set("Error creating label: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute create label on Swing thread", e);
        }

        return result.get();
    }

    /**
     * Creates a function at an already-disassembled instruction.
     *
     * A label is only a symbol, so converting LAB_* into something the
     * decompiler can consume requires a real Function object.  CreateFunctionCmd
     * computes the function body using the same logic as Ghidra's Create
     * Function action.
     */
    private String createFunction(String programName, String addressStr, String name) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address '" + addressStr + "': " + e.getMessage();
        }
        if (addr == null) return "Invalid address: " + addressStr;
        if (!program.getMemory().contains(addr)) return "Address is not in program memory: " + addr;

        String requestedName = (name == null || name.trim().isEmpty()) ? null : name.trim();
        AtomicReference<String> result = new AtomicReference<>("Failed to create function");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function via HTTP");
                boolean success = false;
                try {
                    FunctionManager functionManager = program.getFunctionManager();
                    Function existing = functionManager.getFunctionAt(addr);
                    if (existing != null) {
                        result.set("Function already exists: " + existing.getName() +
                            " at " + existing.getEntryPoint());
                        return;
                    }

                    Function containing = functionManager.getFunctionContaining(addr);
                    if (containing != null) {
                        result.set("Cannot create function at " + addr +
                            ": address is inside function " + containing.getName() +
                            " at " + containing.getEntryPoint());
                        return;
                    }

                    if (program.getListing().getInstructionAt(addr) == null) {
                        result.set("Cannot create function at " + addr +
                            ": no instruction is defined at this address; disassemble it first");
                        return;
                    }

                    CreateFunctionCmd cmd = requestedName == null
                        ? new CreateFunctionCmd(addr)
                        : new CreateFunctionCmd(requestedName, addr, null, SourceType.USER_DEFINED);

                    if (!cmd.applyTo(program, new ConsoleTaskMonitor())) {
                        String status = cmd.getStatusMsg();
                        result.set("Failed to create function at " + addr +
                            (status == null || status.isEmpty() ? "" : ": " + status));
                        return;
                    }

                    Function created = functionManager.getFunctionAt(addr);
                    if (created == null) {
                        result.set("Failed to create function at " + addr +
                            ": Ghidra reported success but no function was created");
                        return;
                    }

                    success = true;
                    result.set("Function created: " + created.getName() + " at " +
                        created.getEntryPoint() + " (body " + created.getBody().getMinAddress() +
                        " - " + created.getBody().getMaxAddress() + ")");
                } catch (Exception e) {
                    Msg.error(this, "Error creating function", e);
                    result.set("Error creating function: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Msg.error(this, "Create function interrupted", e);
            return "Create function interrupted";
        } catch (InvocationTargetException e) {
            Msg.error(this, "Failed to execute create function on Swing thread", e);
            Throwable cause = e.getCause();
            return "Error creating function: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }

        return result.get();
    }

    private String createEnum(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create enum");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            int size = body.has("size") ? body.get("size").getAsInt() : 4;
            JsonArray values = body.getAsJsonArray("values");
            if (size != 1 && size != 2 && size != 4 && size != 8) {
                return "Enum size must be 1, 2, 4, or 8 bytes";
            }
            if (values == null || values.isEmpty()) return "Enum values are required";
            CategoryPath category = getCategoryPath(body);
            String description = getOptionalJsonString(body, "description");

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    EnumDataType enumType = new EnumDataType(category, name, size, dtm);
                    if (description != null) enumType.setDescription(description);

                    for (JsonElement el : values) {
                        JsonObject entry = el.getAsJsonObject();
                        String entryName = entry.get("name").getAsString();
                        long entryValue = entry.get("value").getAsLong();
                        enumType.add(entryName, entryValue);
                    }

                    DataType stored = dtm.addDataType(enumType, DataTypeConflictHandler.REPLACE_HANDLER);
                    success = true;
                    result.set("Enum '" + stored.getPathName() + "' created with " +
                        values.size() + " values (" + stored.getLength() + " bytes)");
                } catch (Exception e) {
                    Msg.error(this, "Error creating enum", e);
                    result.set("Error creating enum: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String createStruct(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create struct");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            JsonArray fields = body.getAsJsonArray("fields");
            if (fields == null) return "Struct fields are required";
            CategoryPath category = getCategoryPath(body);
            int requestedSize = body.has("size") ? body.get("size").getAsInt() : 0;
            if (requestedSize < 0) return "Struct size cannot be negative";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create struct");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    StructureDataType candidate = new StructureDataType(category, name, 0, dtm);
                    DataType stored = dtm.addDataType(candidate, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (!(stored instanceof ghidra.program.model.data.Structure)) {
                        throw new IllegalArgumentException("A non-struct type already uses " + stored.getPathName());
                    }
                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) stored;
                    while (struct.getNumComponents() > 0) struct.delete(0);
                    configureComposite(struct, body);
                    addCompositeFields(struct, fields, dtm, true);
                    if (requestedSize > 0) {
                        if (struct.getLength() > requestedSize) {
                            throw new IllegalArgumentException("Fields require " + struct.getLength() +
                                " bytes, exceeding requested struct size " + requestedSize);
                        }
                        struct.setLength(requestedSize);
                    }
                    success = true;
                    result.set("Struct '" + struct.getPathName() + "' created with " + fields.size() +
                        " fields, total size: " + struct.getLength() + " bytes");
                } catch (Exception e) {
                    Msg.error(this, "Error creating struct", e);
                    result.set("Error creating struct: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    private String createUnion(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create union");
        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            JsonArray fields = body.getAsJsonArray("fields");
            if (fields == null || fields.isEmpty()) return "Union fields are required";
            CategoryPath category = getCategoryPath(body);

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create union");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    UnionDataType candidate = new UnionDataType(category, name, dtm);
                    DataType stored = dtm.addDataType(candidate, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (!(stored instanceof ghidra.program.model.data.Union)) {
                        throw new IllegalArgumentException("A non-union type already uses " + stored.getPathName());
                    }
                    ghidra.program.model.data.Union union = (ghidra.program.model.data.Union) stored;
                    while (union.getNumComponents() > 0) union.delete(0);
                    configureComposite(union, body);
                    addCompositeFields(union, fields, dtm, false);
                    success = true;
                    result.set("Union '" + union.getPathName() + "' created with " + fields.size() +
                        " fields, total size: " + union.getLength() + " bytes");
                } catch (Exception e) {
                    Msg.error(this, "Error creating union", e);
                    result.set("Error creating union: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }
        return result.get();
    }

    private String createTypedef(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create typedef");
        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            String baseTypeName = getRequiredJsonString(body, "base_type");
            CategoryPath category = getCategoryPath(body);

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create typedef");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseType = resolveDataType(dtm, baseTypeName);
                    if (baseType == null) {
                        throw new IllegalArgumentException("Unknown base data type: " + baseTypeName);
                    }
                    TypedefDataType typedef = new TypedefDataType(category, name, baseType, dtm);
                    DataType stored = dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);
                    success = true;
                    result.set("Typedef '" + stored.getPathName() + "' created for " +
                        baseType.getDisplayName() + " (" + stored.getLength() + " bytes)");
                } catch (Exception e) {
                    Msg.error(this, "Error creating typedef", e);
                    result.set("Error creating typedef: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }
        return result.get();
    }

    private String parseCTypes(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to parse C types");
        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String code = getRequiredJsonString(body, "code");
            CategoryPath category = getCategoryPath(body);
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Parse C data types");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Set<Long> existingIds = new HashSet<>();
                    Iterator<DataType> beforeIterator = dtm.getAllDataTypes();
                    while (beforeIterator.hasNext()) existingIds.add(dtm.getID(beforeIterator.next()));
                    int before = dtm.getDataTypeCount(false);
                    CParser parser = new CParser(dtm, true, new DataTypeManager[0]);
                    DataType last = parser.parse(code);
                    int added = Math.max(0, dtm.getDataTypeCount(false) - before);
                    if (!category.isRoot()) {
                        dtm.createCategory(category);
                        Iterator<DataType> afterIterator = dtm.getAllDataTypes();
                        while (afterIterator.hasNext()) {
                            DataType parsedType = afterIterator.next();
                            if (!existingIds.contains(dtm.getID(parsedType)) &&
                                    (parsedType instanceof Composite ||
                                     parsedType instanceof ghidra.program.model.data.Enum ||
                                     parsedType instanceof TypeDef ||
                                     parsedType instanceof ghidra.program.model.data.FunctionDefinition)) {
                                parsedType.setCategoryPath(category);
                            }
                        }
                    }
                    String messages = parser.getParseMessages();
                    success = true;
                    result.set("C declarations parsed; data types added: " + added +
                        "; category: " + category.getPath() +
                        (last == null ? "" : "; last type: " + last.getPathName()) +
                        (messages == null || messages.isBlank() ? "" : "\nParser messages:\n" + messages));
                } catch (Exception e) {
                    Msg.error(this, "Error parsing C types", e);
                    result.set("Error parsing C types: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }
        return result.get();
    }

    private void configureComposite(Composite composite, JsonObject body) {
        String description = getOptionalJsonString(body, "description");
        if (description != null) composite.setDescription(description);
        boolean packed = body.has("packed") && body.get("packed").getAsBoolean();
        int packing = body.has("packing") ? body.get("packing").getAsInt() : 0;
        int alignment = body.has("alignment") ? body.get("alignment").getAsInt() : 0;
        if (packing < 0 || alignment < 0) {
            throw new IllegalArgumentException("Packing and alignment cannot be negative");
        }
        if (packing > 0) composite.setExplicitPackingValue(packing);
        else composite.setPackingEnabled(packed);
        if (alignment > 0) composite.setExplicitMinimumAlignment(alignment);
    }

    private void addCompositeFields(Composite composite, JsonArray fields, DataTypeManager dtm,
                                    boolean allowOffsets) throws Exception {
        for (JsonElement element : fields) {
            JsonObject field = element.getAsJsonObject();
            String fieldName = getRequiredJsonString(field, "name");
            String fieldType = getRequiredJsonString(field, "type");
            String comment = getOptionalJsonString(field, "comment");
            DataType dt = resolveDataType(dtm, fieldType);
            if (dt == null) throw new IllegalArgumentException("Unknown field type: " + fieldType);

            if (field.has("bit_size")) {
                if (field.has("offset")) {
                    throw new IllegalArgumentException("Explicit offsets for bit-fields are not supported; use C declarations");
                }
                composite.addBitField(dt, field.get("bit_size").getAsInt(), fieldName, comment);
                continue;
            }

            int fieldSize = field.has("size") ? field.get("size").getAsInt() : dt.getLength();
            if (fieldSize <= 0) {
                throw new IllegalArgumentException("Field '" + fieldName +
                    "' requires an explicit positive size");
            }
            if (field.has("offset")) {
                if (!allowOffsets || !(composite instanceof ghidra.program.model.data.Structure)) {
                    throw new IllegalArgumentException("Explicit offsets are only valid for structs");
                }
                int offset = field.get("offset").getAsInt();
                if (offset < 0) throw new IllegalArgumentException("Field offset cannot be negative");
                ((ghidra.program.model.data.Structure) composite).insertAtOffset(
                    offset, dt, fieldSize, fieldName, comment);
            } else {
                composite.add(dt, fieldSize, fieldName, comment);
            }
        }
    }

    private CategoryPath getCategoryPath(JsonObject body) {
        String category = getOptionalJsonString(body, "category");
        if (category == null || category.isBlank() || category.equals("/")) return CategoryPath.ROOT;
        if (!category.startsWith("/")) category = "/" + category;
        return new CategoryPath(category);
    }

    private String getRequiredJsonString(JsonObject body, String key) {
        String value = getOptionalJsonString(body, key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("JSON field '" + key + "' is required");
        }
        return value.trim();
    }

    private String getOptionalJsonString(JsonObject body, String key) {
        return body.has(key) && !body.get(key).isJsonNull() ? body.get(key).getAsString() : null;
    }

    private String applyDataType(String programName, String addressStr, String dataTypeName,
                                 boolean clearExisting, String label) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (dataTypeName == null || dataTypeName.isBlank()) return "Data type is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to apply data type");
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply data type via HTTP");
                boolean success = false;
                try {
                    Address start = program.getAddressFactory().getAddress(addressStr);
                    if (start == null) throw new IllegalArgumentException("Invalid address: " + addressStr);
                    DataType dt = resolveDataType(program.getDataTypeManager(), dataTypeName);
                    if (dt == null) throw new IllegalArgumentException("Unknown data type: " + dataTypeName);
                    if (dt.getLength() <= 0) {
                        throw new IllegalArgumentException("Data type has no fixed positive length: " +
                            dt.getDisplayName());
                    }
                    Address end = start.add(dt.getLength() - 1L);
                    if (!program.getMemory().contains(start) || !program.getMemory().contains(end)) {
                        throw new IllegalArgumentException("Data type range " + start + " - " + end +
                            " is outside program memory");
                    }

                    Listing listing = program.getListing();
                    InstructionIterator instructions = listing.getInstructions(start, true);
                    if (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        if (instruction.getAddress().compareTo(end) <= 0) {
                            throw new IllegalArgumentException("Instruction at " + instruction.getAddress() +
                                " overlaps the target range; code is never cleared automatically");
                        }
                    }

                    if (clearExisting) listing.clearCodeUnits(start, end, false);
                    Data created = listing.createData(start, dt);
                    if (label != null && !label.isBlank()) {
                        program.getSymbolTable().createLabel(
                            start, label.trim(), SourceType.USER_DEFINED);
                    }
                    success = true;
                    result.set("Applied " + created.getDataType().getPathName() + " at " + start +
                        " (" + created.getLength() + " bytes)" +
                        (label == null || label.isBlank() ? "" : "; label: " + label.trim()));
                } catch (Exception e) {
                    Msg.error(this, "Error applying data type", e);
                    result.set("Error applying data type: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Apply data type interrupted";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "Error applying data type: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }
        return result.get();
    }

    private String applyStruct(String programName, String addressStr, String structName) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        DataType dt = resolveDataType(program.getDataTypeManager(), structName);
        if (!(dt instanceof ghidra.program.model.data.Structure)) {
            return "Struct '" + structName + "' not found";
        }
        return applyDataType(programName, addressStr, structName, true, null);
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=", 2);
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Read raw request body as a string (for JSON endpoints).
     */
    private String readRequestBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private boolean parseBooleanOrDefault(String val, boolean defaultValue) {
        if (val == null || val.isBlank()) return defaultValue;
        if (val.equalsIgnoreCase("true") || val.equals("1") || val.equalsIgnoreCase("yes")) return true;
        if (val.equalsIgnoreCase("false") || val.equals("0") || val.equalsIgnoreCase("no")) return false;
        return defaultValue;
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null && pm.getCurrentProgram() != null) {
            return pm.getCurrentProgram();
        }
        // ProgramManager returns null when plugin is loaded via Code Browser
        // instead of a tool that directly provides ProgramManager. Fall back
        // to CodeViewerService which is always available in Code Browser.
        CodeViewerService cvs = tool.getService(CodeViewerService.class);
        if (cvs != null && cvs.getNavigatable() != null) {
            return cvs.getNavigatable().getProgram();
        }
        return null;
    }

    /**
     * Resolve a program among the tool's open programs by name or domain-file path.
     * When {@code programName} is null or empty this falls back to the current
     * (focused) program, preserving the previous single-program behavior.
     *
     * @param programName a program name (e.g. "ping"), domain-file name, or full
     *                    project path (e.g. "/folder/ping"); null/empty for current
     * @return the matching open Program, or null if none matches
     */
    private Program getProgramByName(String programName) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (programName == null || programName.isEmpty()) {
            return getCurrentProgram();
        }
        if (pm == null) return null;
        for (Program p : pm.getAllOpenPrograms()) {
            if (p.getName().equals(programName)
                    || p.getDomainFile().getName().equals(programName)
                    || p.getDomainFile().getPathname().equals(programName)) {
                return p;
            }
        }
        return null;
    }

    /**
     * List every program currently open in the tool, marking the focused one.
     * Each line is "name\tpath[\t(current)]".
     */
    private String listOpenPrograms() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "Program manager not available";

        Program current = pm.getCurrentProgram();
        List<String> lines = new ArrayList<>();
        for (Program p : pm.getAllOpenPrograms()) {
            String marker = (p == current) ? "\t(current)" : "";
            lines.add(String.format("%s\t%s%s",
                p.getName(), p.getDomainFile().getPathname(), marker));
        }
        if (lines.isEmpty()) return "No programs open";
        return String.join("\n", lines);
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
