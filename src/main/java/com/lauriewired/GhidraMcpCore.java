package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import com.sun.net.httpserver.HttpServer;

import java.util.*;

/**
 * Wires the GhidraMCP tool domains together: the original tools (one class per
 * domain, see {@link CoreTool}) and the newer tool groups. Programs are resolved
 * through {@link McpEnvironment}, so the same code serves the project window,
 * any CodeBrowser and headless mode.
 */
public class GhidraMcpCore {

    private final McpEnvironment env;
    private final McpRuntime runtime;
    final DecompilerService decompiler = new DecompilerService();
    private final List<CoreTool> domains = new ArrayList<>();

    GhidraMcpCore(McpEnvironment env, McpRuntime runtime) {
        this.env = env;
        this.runtime = runtime;
        domains.add(new ListingTools(env, decompiler));
        domains.add(new FunctionEditTools(env, decompiler));
        domains.add(new AnnotationTools(env, decompiler));
        domains.add(new InstructionPatternTools(env, decompiler));
        domains.add(new DataTools(env, decompiler));
        domains.add(new TypeTools(env, decompiler));
    }

    void dispose() {
        decompiler.disposeAll();
    }

    /** Registers the MCP endpoint (the only HTTP context). */
    void registerEndpoints(HttpServer server) {
        server.createContext("/mcp", buildMcpServer()).getFilters().add(McpServer.originFilter());
    }

    // ----------------------------------------------------------------------------------
    // MCP tool definitions (Streamable HTTP endpoint at /mcp)
    // ----------------------------------------------------------------------------------

    private static final String MCP_INSTRUCTIONS =
        "Ghidra reverse-engineering tools. Program-scoped tools take an optional 'program' "
            + "(name or project path from list_open_programs); empty means the current program.";

    McpServer buildMcpServer() {
        McpServer mcp = new McpServer("ghidra-mcp", McpRuntime.VERSION, MCP_INSTRUCTIONS);
        for (CoreTool d : domains) {
            d.registerMcp(mcp);
        }
        registerToolGroups(mcp);
        return mcp;
    }

    /** Newer tool groups (each registers its own MCP tools). */
    private void registerToolGroups(McpServer mcp) {
        new ServerTools(env, runtime).register(mcp);
        new ProjectTools(env).register(mcp);
        new AnalysisTools(env).register(mcp);
        new DecompilerTools(env, decompiler).register(mcp);
        new FunctionTools(env, decompiler).register(mcp);
        new SymbolTools(env).register(mcp);
        new CodeAnalysisTools(env, decompiler).register(mcp);
        new TypeEditTools(env).register(mcp);
        new MemoryTools(env).register(mcp);
        new PromptTools(env, decompiler).register(mcp);
        new ScriptTools(env).register(mcp);
    }
}
