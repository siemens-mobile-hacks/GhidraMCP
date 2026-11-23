package com.lauriewired;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

/** Option registration and runtime acquisition shared by both plugins. */
final class McpPluginSupport {

    static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    static final String HOST_OPTION_NAME = "Server Host";
    static final String PORT_OPTION_NAME = "Server Port";
    static final String DEFAULT_HOST = "127.0.0.1";
    static final int DEFAULT_PORT = 8080;

    private McpPluginSupport() {
    }

    static void registerOptions(PluginTool tool) {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(HOST_OPTION_NAME, DEFAULT_HOST, null,
            "The network interface address for the embedded HTTP server. "
                + "Use 127.0.0.1 for local-only access. Requires plugin reload to take effect.");
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT, null,
            "The network port number the embedded HTTP server will listen on. "
                + "Requires Ghidra restart or plugin reload to take effect after changing.");
    }

    /** Acquires the shared runtime with this tool's host/port options. */
    static McpRuntime acquire(Object owner, PluginTool tool) {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        String configuredHost = options.getString(HOST_OPTION_NAME, DEFAULT_HOST).trim();
        String host = configuredHost.isEmpty() ? DEFAULT_HOST : configuredHost;
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        try {
            return McpRuntime.acquire(owner, host, port, McpEnvironment::gui);
        }
        catch (Exception e) {
            Msg.error(owner, "Failed to start GhidraMCP server on " + host + ":" + port
                + ". Address or port might be unavailable.", e);
            return null;
        }
    }
}
