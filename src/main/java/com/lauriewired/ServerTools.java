package com.lauriewired;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import ghidra.framework.Application;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/** Server metadata and shutdown. */
final class ServerTools {

    private final McpEnvironment env;
    private final McpRuntime runtime;

    ServerTools(McpEnvironment env, McpRuntime runtime) {
        this.env = env;
        this.runtime = runtime;
    }

    void register(McpServer mcp) {
        mcp.tool("get_server_info",
                "Describe the GhidraMCP server: plugin and Ghidra versions, mode (GUI/headless), "
                    + "active project, running tool windows and open programs.")
            .handler(a -> serverInfo());

        mcp.tool("shutdown_ghidra",
                "Exit Ghidra (headless: stop the server and end the script). Refuses when open "
                    + "programs have unsaved changes unless save=true (save them first) or "
                    + "force=true (discard them).")
            .optBoolean("save", false, "Save programs with unsaved changes before exiting")
            .optBoolean("force", false, "Exit even if changes would be lost")
            .handler(a -> shutdown(a.bool("save"), a.bool("force")));
    }

    private String serverInfo() {
        StringBuilder sb = new StringBuilder();
        sb.append("GhidraMCP ").append(McpRuntime.VERSION)
            .append(" on Ghidra ").append(Application.getApplicationVersion())
            .append(" ").append(Application.getApplicationReleaseName()).append('\n');
        sb.append("Mode: ").append(env.isHeadless() ? "headless" : "GUI").append('\n');
        sb.append("Server: http://").append(runtime.host()).append(':').append(runtime.port())
            .append("/mcp (started ").append(Instant.ofEpochMilli(runtime.startedAt())).append(")\n");
        sb.append("Server owners: ").append(McpRuntime.ownerSummary()).append('\n');
        Project project = env.project();
        sb.append("Project: ").append(project == null ? "(none)"
            : project.getName() + " at " + project.getProjectLocator().getProjectDir()).append('\n');
        List<PluginTool> tools = env.runningTools();
        sb.append("Tool windows: ");
        if (tools.isEmpty()) {
            sb.append("(none)");
        }
        else {
            List<String> names = new ArrayList<>();
            for (PluginTool t : tools) names.add(t.getName());
            sb.append(String.join(", ", names));
        }
        sb.append('\n');
        List<McpEnvironment.OpenProgram> programs = env.openPrograms();
        sb.append("Open programs: ").append(programs.size()).append('\n');
        for (McpEnvironment.OpenProgram op : programs) {
            sb.append("  ").append(op.program.getDomainFile().getPathname())
                .append(" [").append(op.location()).append(']')
                .append(op.current ? " (current)" : "")
                .append(op.program.isChanged() ? " (unsaved changes)" : "").append('\n');
        }
        return sb.toString().trim();
    }

    private String shutdown(boolean save, boolean force) throws Exception {
        List<Program> dirty = new ArrayList<>();
        for (McpEnvironment.OpenProgram op : env.openPrograms()) {
            if (op.program.isChanged()) dirty.add(op.program);
        }
        if (!dirty.isEmpty() && !save && !force) {
            StringBuilder sb = new StringBuilder("Refusing to exit: unsaved changes in");
            for (Program p : dirty) sb.append("\n  ").append(p.getDomainFile().getPathname());
            sb.append("\nPass save=true to save them or force=true to discard them.");
            throw McpSupport.fail(sb.toString());
        }
        if (save) {
            for (Program p : dirty) {
                if (p.getDomainFile().isReadOnly()) {
                    throw McpSupport.fail("Cannot save read-only program " + p.getDomainFile().getPathname()
                        + "; use force=true to discard its changes");
                }
                p.getDomainFile().save(TaskMonitor.DUMMY);
            }
        }
        if (env.isHeadless()) {
            GhidraMcpHeadless.requestStop();
            return "Headless server stopping" + (save ? " (saved " + dirty.size() + " program(s))" : "");
        }
        boolean discard = force && !dirty.isEmpty();
        // Exit after this response has been written.
        Thread exitThread = new Thread(() -> {
            try {
                Thread.sleep(500);
            }
            catch (InterruptedException e) {
                return;
            }
            if (discard) {
                Msg.info(ServerTools.class, "shutdown_ghidra: forcing exit, discarding unsaved changes");
                System.exit(0);
            }
            Swing.runLater(AppInfo::exitGhidra);
        }, "GhidraMCP-shutdown");
        exitThread.setDaemon(true);
        exitThread.start();
        return "Ghidra is exiting" + (save ? " (saved " + dirty.size() + " program(s))" : "")
            + (discard ? " (discarding unsaved changes)" : "");
    }
}
