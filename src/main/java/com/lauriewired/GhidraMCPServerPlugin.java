package com.lauriewired;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Project-window (front end) plugin: runs the GhidraMCP server as soon as
 * Ghidra starts, without any CodeBrowser window, and enables project
 * management tools (open/close projects, import, open programs in background).
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidraMCP server (project window)",
    description = "Runs the GhidraMCP HTTP/MCP server for the whole Ghidra session, "
        + "independent of CodeBrowser windows."
)
public class GhidraMCPServerPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

    public GhidraMCPServerPlugin(PluginTool tool) {
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
