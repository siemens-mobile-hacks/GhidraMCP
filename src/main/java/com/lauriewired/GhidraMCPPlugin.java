package com.lauriewired;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * CodeBrowser-level plugin. It only keeps the shared GhidraMCP server alive
 * while the window is open; programs from every window are reachable through
 * the server regardless of which window started it.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhidraMCP server (CodeBrowser)",
    description = "Starts the shared GhidraMCP HTTP/MCP server while a CodeBrowser is open. "
        + "Enable GhidraMCPServerPlugin in the project window to run it without a CodeBrowser."
)
public class GhidraMCPPlugin extends Plugin {

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        McpPluginSupport.registerOptions(tool);
        McpPluginSupport.acquire(this, tool);
    }

    @Override
    public void dispose() {
        McpRuntime.release(this);
        super.dispose();
    }
}
