package com.lauriewired;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import docking.DockingWindowManager;
import docking.Tool;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Locates projects, tools and programs for the MCP server independently of the
 * plugin instance that started it.
 *
 * <p>In the GUI the active project and every running tool (CodeBrowser windows)
 * are discovered on each request, so programs opened in any window are
 * reachable. Programs the server opens itself without a window ("background"
 * programs) are tracked in a registry. In headless mode the project and the
 * programs come from the headless script.
 */
final class McpEnvironment {

    /** One open program and where it is open. */
    static final class OpenProgram {
        final Program program;
        final PluginTool tool; // null for background/headless programs
        final boolean current;

        OpenProgram(Program program, PluginTool tool, boolean current) {
            this.program = program;
            this.tool = tool;
            this.current = current;
        }

        String location() {
            return tool == null ? "background" : tool.getName();
        }
    }

    /** Thrown when a program selector does not identify exactly one program. */
    static final class ProgramResolutionException extends RuntimeException {
        ProgramResolutionException(String message) {
            super(message);
        }
    }

    private final Project headlessProject;
    /** Programs opened by the server itself, keyed by project path. */
    private final Map<String, Program> backgroundPrograms = new LinkedHashMap<>();
    /** Program the headless script or an MCP open/import marked as current. */
    private volatile Program preferredProgram;
    /** Focused window when preferredProgram was set; a focus change hands "current" back to the GUI. */
    private volatile Object preferredFocus;

    private McpEnvironment(Project headlessProject) {
        this.headlessProject = headlessProject;
    }

    static McpEnvironment gui() {
        return new McpEnvironment(null);
    }

    static McpEnvironment headless(Project project, Program initialProgram) {
        McpEnvironment env = new McpEnvironment(project);
        if (initialProgram != null) {
            env.preferredProgram = initialProgram;
        }
        return env;
    }

    boolean isHeadless() {
        return headlessProject != null;
    }

    // ------------------------------------------------------------------
    // Project and tools
    // ------------------------------------------------------------------

    Project project() {
        if (headlessProject != null) return headlessProject;
        return AppInfo.getActiveProject();
    }

    /** Running tools of the active project (CodeBrowser windows, debugger, ...). */
    List<PluginTool> runningTools() {
        List<PluginTool> tools = new ArrayList<>();
        Project project = project();
        if (project == null || headlessProject != null) return tools;
        ToolManager tm = project.getToolManager();
        if (tm == null) return tools;
        for (PluginTool t : tm.getRunningTools()) {
            tools.add(t);
        }
        return tools;
    }

    /** The tool whose window was focused most recently and that can show programs. */
    PluginTool activeProgramTool() {
        if (headlessProject != null) return null;
        AtomicReference<Tool> active = new AtomicReference<>();
        Swing.runNow(() -> {
            DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
            if (dwm != null) active.set(dwm.getTool());
        });
        List<PluginTool> tools = runningTools();
        if (active.get() instanceof PluginTool && tools.contains(active.get())) {
            PluginTool t = (PluginTool) active.get();
            if (t.getService(ProgramManager.class) != null) return t;
        }
        PluginTool firstWithProgram = null;
        for (PluginTool t : tools) {
            ProgramManager pm = t.getService(ProgramManager.class);
            if (pm == null) continue;
            if (pm.getCurrentProgram() != null) return t;
            if (firstWithProgram == null) firstWithProgram = t;
        }
        return firstWithProgram;
    }

    CodeViewerService activeCodeViewer() {
        PluginTool t = activeProgramTool();
        return t == null ? null : t.getService(CodeViewerService.class);
    }

    DataTypeManagerService dataTypeManagerService() {
        PluginTool t = activeProgramTool();
        return t == null ? null : t.getService(DataTypeManagerService.class);
    }

    // ------------------------------------------------------------------
    // Programs
    // ------------------------------------------------------------------

    /**
     * Every open program, deduplicated: tool-hosted entries first, then background ones.
     * Not synchronized as a whole: currentProgram() may wait for the Swing thread, and the
     * Swing thread may call this method (holding the lock there would deadlock).
     */
    List<OpenProgram> openPrograms() {
        List<OpenProgram> result = new ArrayList<>();
        Program current = currentProgram();
        List<Program> seen = new ArrayList<>();
        for (PluginTool t : runningTools()) {
            ProgramManager pm = t.getService(ProgramManager.class);
            if (pm == null) continue;
            for (Program p : pm.getAllOpenPrograms()) {
                if (seen.contains(p)) continue;
                seen.add(p);
                result.add(new OpenProgram(p, t, p == current));
            }
        }
        List<Program> background;
        synchronized (this) {
            pruneClosedBackgroundPrograms();
            background = new ArrayList<>(backgroundPrograms.values());
        }
        for (Program p : background) {
            if (seen.contains(p)) continue;
            seen.add(p);
            result.add(new OpenProgram(p, null, p == current));
        }
        return result;
    }

    /**
     * The current program: the one opened/imported last through MCP until the
     * user focuses another window, otherwise the program of the focused
     * CodeBrowser, otherwise the only background program.
     */
    Program currentProgram() {
        Program preferred = preferredProgram;
        if (preferred != null && !preferred.isClosed()
                && (isHeadless() || focusedWindowManager() == preferredFocus)) {
            return preferred;
        }
        PluginTool t = activeProgramTool();
        if (t != null) {
            ProgramManager pm = t.getService(ProgramManager.class);
            if (pm != null && pm.getCurrentProgram() != null) return pm.getCurrentProgram();
        }
        if (preferred != null && !preferred.isClosed()) return preferred;
        synchronized (this) {
            pruneClosedBackgroundPrograms();
            if (backgroundPrograms.size() == 1) {
                return backgroundPrograms.values().iterator().next();
            }
        }
        return null;
    }

    void setPreferredProgram(Program program) {
        this.preferredFocus = isHeadless() ? null : focusedWindowManager();
        this.preferredProgram = program;
    }

    private Object focusedWindowManager() {
        if (isHeadless()) return null;
        AtomicReference<Object> active = new AtomicReference<>();
        Swing.runNow(() -> active.set(DockingWindowManager.getActiveInstance()));
        return active.get();
    }

    /**
     * Resolves a program selector: empty means the current program; otherwise
     * a program name, domain-file name or project path ("/folder/name").
     * Returns null when nothing matches; throws when the selector is ambiguous.
     */
    Program resolveProgram(String selector) {
        if (selector == null || selector.isBlank()) {
            return currentProgram();
        }
        String sel = selector.trim();
        List<Program> exact = new ArrayList<>();
        List<Program> byName = new ArrayList<>();
        for (OpenProgram op : openPrograms()) {
            Program p = op.program;
            DomainFile df = p.getDomainFile();
            if (df.getPathname().equals(sel)) {
                exact.add(p);
            }
            else if (p.getName().equals(sel) || df.getName().equals(sel)) {
                byName.add(p);
            }
        }
        if (!exact.isEmpty()) return exact.get(0);
        if (byName.size() == 1) return byName.get(0);
        if (byName.size() > 1) {
            StringBuilder sb = new StringBuilder("Program name '" + sel
                + "' is ambiguous; use one of these project paths:");
            for (Program p : byName) {
                sb.append("\n  ").append(p.getDomainFile().getPathname());
            }
            throw new ProgramResolutionException(sb.toString());
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Background programs
    // ------------------------------------------------------------------

    synchronized Program findBackgroundProgram(DomainFile file) {
        pruneClosedBackgroundPrograms();
        return backgroundPrograms.get(file.getPathname());
    }

    /** Opens a project file without a window; the environment is the consumer. */
    synchronized Program openBackground(DomainFile file, TaskMonitor monitor)
            throws IOException, CancelledException, VersionException {
        Program existing = findBackgroundProgram(file);
        if (existing != null) return existing;
        DomainObject obj = file.getDomainObject(this, false, false, monitor);
        if (!(obj instanceof Program)) {
            obj.release(this);
            throw new IOException(file.getPathname() + " is not a program (" + file.getContentType() + ")");
        }
        Program program = (Program) obj;
        backgroundPrograms.put(file.getPathname(), program);
        return program;
    }

    /** Registers a program opened elsewhere (headless script) and adds this environment as consumer. */
    synchronized void adoptBackground(Program program) {
        if (backgroundPrograms.containsValue(program)) return;
        program.addConsumer(this);
        backgroundPrograms.put(program.getDomainFile().getPathname(), program);
    }

    /** Releases a background program; returns false when the server did not open it. */
    synchronized boolean releaseBackground(Program program) {
        String key = null;
        for (Map.Entry<String, Program> e : backgroundPrograms.entrySet()) {
            if (e.getValue() == program) {
                key = e.getKey();
                break;
            }
        }
        if (key == null) return false;
        backgroundPrograms.remove(key);
        if (preferredProgram == program) preferredProgram = null;
        program.release(this);
        return true;
    }

    synchronized boolean isBackground(Program program) {
        return backgroundPrograms.containsValue(program);
    }

    synchronized void releaseAll() {
        for (Program p : new ArrayList<>(backgroundPrograms.values())) {
            try {
                p.release(this);
            }
            catch (Exception e) {
                // ignore during shutdown
            }
        }
        backgroundPrograms.clear();
        preferredProgram = null;
    }

    /** Keeps background entries whose domain file moved in sync and drops closed programs. */
    private void pruneClosedBackgroundPrograms() {
        Map<String, Program> refreshed = new LinkedHashMap<>();
        for (Program p : backgroundPrograms.values()) {
            if (p.isClosed()) continue;
            refreshed.put(p.getDomainFile().getPathname(), p);
        }
        backgroundPrograms.clear();
        backgroundPrograms.putAll(refreshed);
    }
}
