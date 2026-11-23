package com.lauriewired;

import java.io.File;
import java.lang.reflect.Method;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.model.ToolServices;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/** Project, project-file and program lifecycle tools. */
final class ProjectTools {

    private final McpEnvironment env;

    ProjectTools(McpEnvironment env) {
        this.env = env;
    }

    void register(McpServer mcp) {
        mcp.tool("get_project",
                "Describe the active Ghidra project: name, location, number of files and folders, "
                    + "and the programs currently open (and where).")
            .handler(a -> getProject());

        mcp.tool("list_project_files",
                "List folders and files of the active project. Folders end with '/'. Each file shows "
                    + "its content type, version, modification time and whether it is open (and where).")
            .optString("folder", "/", "Project folder to list")
            .optBoolean("recursive", false, "Descend into sub-folders (lists files only)")
            .optString("filter", "", "Case-insensitive substring or glob (*, ?) matched against the path")
            .optString("content_type", "", "Only files of this content type, e.g. Program")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 200, "Maximum number of entries")
            .handler(a -> listFiles(a.str("folder"), a.bool("recursive"), a.str("filter"),
                a.str("content_type"), a.integer("offset"), a.integer("limit")));

        mcp.tool("get_program_info",
                "Program metadata: project path, language, compiler spec, processor, endianness, "
                    + "address size, image base, address range, memory size, executable format/path/hashes, "
                    + "function and symbol counts, analysis state, unsaved changes.")
            .program()
            .handler(a -> programInfo(McpSupport.program(env, a.str("program"))));

        mcp.tool("open_program",
                "Open a program from the project. mode=background opens it without a window "
                    + "(works in the project window and headless); mode=tool opens it in a CodeBrowser "
                    + "(the focused one, or a new default tool). The opened program becomes current.")
            .string("path", "Project path of the program, e.g. /folder/firmware.bin")
            .optString("mode", "background", "\"background\" or \"tool\"")
            .optBoolean("new_window", false, "mode=tool: always open a new CodeBrowser window")
            .handler(a -> openProgram(a.str("path"), a.str("mode"), a.bool("new_window")));

        mcp.tool("close_program",
                "Close an open program. Refuses when it has unsaved changes unless save=true "
                    + "or discard=true.")
            .program()
            .optBoolean("save", false, "Save changes before closing")
            .optBoolean("discard", false, "Close and discard unsaved changes")
            .handler(a -> closeProgram(McpSupport.program(env, a.str("program")),
                a.bool("save"), a.bool("discard")));

        mcp.tool("save_program",
                "Save a program's changes to the project (Ghidra 'Save'). all=true saves every open "
                    + "program with unsaved changes.")
            .program()
            .optBoolean("all", false, "Save all open programs with unsaved changes")
            .handler(a -> save(a.str("program"), a.bool("all")));

        mcp.tool("import_file",
                "Import a file from disk into the project (like File > Import File). By default the "
                    + "loader and language are detected automatically. The new program is saved, and "
                    + "opened in the background unless open=false. Run analyze_program afterwards.")
            .string("file_path", "Absolute path of the file on disk")
            .optString("folder", "/", "Destination project folder (created if missing)")
            .optString("name", "", "Program name in the project (default: file name)")
            .optString("language", "", "Language ID, e.g. ARM:LE:32:Cortex (default: auto)")
            .optString("compiler", "", "Compiler spec ID, e.g. default (default: auto)")
            .optString("loader", "", "Loader name, e.g. \"Raw Binary\" or \"Executable and Linking Format (ELF)\"")
            .optString("base_address", "", "Image base / load address (loader option), e.g. 0x8000000")
            .optBoolean("open", true, "Open the imported program in the background")
            .handler(a -> importFile(a));

        mcp.tool("create_project_folder", "Create a folder (and missing parents) in the project.")
            .string("path", "Folder path, e.g. /firmware/v2")
            .handler(a -> createFolder(a.str("path")));

        mcp.tool("rename_project_file", "Rename a project file or folder. Open files cannot be renamed.")
            .string("path", "Project path of the file or folder")
            .string("new_name", "New name (not a path)")
            .handler(a -> renameItem(a.str("path"), a.str("new_name")));

        mcp.tool("move_project_file", "Move a project file or folder into another folder. Open files cannot be moved.")
            .string("path", "Project path of the file or folder")
            .string("destination", "Destination folder path")
            .handler(a -> moveItem(a.str("path"), a.str("destination")));

        mcp.tool("delete_project_file",
                "Permanently delete a project file or an empty folder. Requires confirm=true; "
                    + "open files cannot be deleted.")
            .string("path", "Project path of the file or folder")
            .optBoolean("confirm", false, "Must be true to delete")
            .handler(a -> deleteItem(a.str("path"), a.bool("confirm")));

        if (!env.isHeadless()) {
            mcp.tool("list_recent_projects", "List recently opened Ghidra projects (GUI only).")
                .handler(a -> recentProjects());

            mcp.tool("open_project",
                    "Open another Ghidra project in the project window, closing the current one "
                        + "(GUI only; requires the GhidraMCPServerPlugin in the project window). "
                        + "Refuses when open programs have unsaved changes unless save=true or discard=true.")
                .string("path", "Path of the .gpr file or of the project directory + name, e.g. /work/MyProj.gpr")
                .optBoolean("save", false, "Save unsaved programs first")
                .optBoolean("discard", false, "Discard unsaved changes")
                .handler(a -> openProject(a.str("path"), a.bool("save"), a.bool("discard")));

            mcp.tool("close_project",
                    "Close the active project and all its tool windows (GUI only; requires the "
                        + "GhidraMCPServerPlugin). Same unsaved-changes rules as open_project.")
                .optBoolean("save", false, "Save unsaved programs first")
                .optBoolean("discard", false, "Discard unsaved changes")
                .handler(a -> closeProject(a.bool("save"), a.bool("discard")));

            mcp.tool("create_project",
                    "Create a new non-shared Ghidra project and open it (GUI only; requires the "
                        + "GhidraMCPServerPlugin). The current project is closed first.")
                .string("directory", "Directory that will contain <name>.gpr and <name>.rep")
                .string("name", "Project name")
                .optBoolean("save", false, "Save unsaved programs of the current project first")
                .optBoolean("discard", false, "Discard unsaved changes of the current project")
                .handler(a -> createProject(a.str("directory"), a.str("name"), a.bool("save"),
                    a.bool("discard")));
        }
    }

    // ------------------------------------------------------------------
    // Project information and files
    // ------------------------------------------------------------------

    private Project requireProject() {
        Project p = env.project();
        if (p == null) throw McpSupport.fail("No project is open");
        return p;
    }

    private String getProject() {
        Project p = requireProject();
        ProjectLocator loc = p.getProjectLocator();
        int[] counts = count(p.getProjectData().getRootFolder());
        StringBuilder sb = new StringBuilder();
        sb.append("Project: ").append(p.getName()).append('\n');
        sb.append("Location: ").append(loc.getProjectDir().getParent()).append('\n');
        sb.append("Project file: ").append(loc.getMarkerFile()).append('\n');
        sb.append("Shared: ").append(p.getRepository() != null).append('\n');
        sb.append("Files: ").append(counts[0]).append(", folders: ").append(counts[1]).append('\n');
        List<McpEnvironment.OpenProgram> open = env.openPrograms();
        sb.append("Open programs: ").append(open.isEmpty() ? "(none)" : "").append('\n');
        for (McpEnvironment.OpenProgram op : open) {
            sb.append("  ").append(op.program.getDomainFile().getPathname()).append(" [")
                .append(op.location()).append(']').append(op.current ? " (current)" : "")
                .append(op.program.isChanged() ? " (unsaved changes)" : "").append('\n');
        }
        return sb.toString().trim();
    }

    private static int[] count(DomainFolder folder) {
        int files = folder.getFiles().length;
        int folders = folder.getFolders().length;
        for (DomainFolder sub : folder.getFolders()) {
            int[] c = count(sub);
            files += c[0];
            folders += c[1];
        }
        return new int[] { files, folders };
    }

    private DomainFolder folder(String path) {
        ProjectData data = requireProject().getProjectData();
        String p = path == null || path.isBlank() ? "/" : path.trim();
        DomainFolder f = data.getFolder(p);
        if (f == null) throw McpSupport.fail("Project folder not found: " + p);
        return f;
    }

    private String listFiles(String folderPath, boolean recursive, String filter, String contentType,
            int offset, int limit) {
        DomainFolder root = folder(folderPath);
        Pattern matcher = filterPattern(filter);
        List<String> lines = new ArrayList<>();
        collect(root, recursive, matcher, contentType, lines);
        return McpSupport.page(lines, offset, limit);
    }

    private void collect(DomainFolder folder, boolean recursive, Pattern matcher, String contentType,
            List<String> out) {
        if (!recursive) {
            for (DomainFolder sub : folder.getFolders()) {
                String path = sub.getPathname() + "/";
                if (matches(matcher, path) && (contentType == null || contentType.isEmpty())) {
                    out.add(path);
                }
            }
        }
        for (DomainFile f : folder.getFiles()) {
            if (contentType != null && !contentType.isEmpty()
                    && !contentType.equalsIgnoreCase(f.getContentType())) {
                continue;
            }
            if (!matches(matcher, f.getPathname())) continue;
            out.add(describeFile(f));
        }
        if (recursive) {
            for (DomainFolder sub : folder.getFolders()) {
                collect(sub, true, matcher, contentType, out);
            }
        }
    }

    private String describeFile(DomainFile f) {
        StringBuilder sb = new StringBuilder(f.getPathname());
        sb.append("\ttype=").append(f.getContentType());
        if (f.isVersioned()) sb.append("\tversion=").append(f.getVersion());
        sb.append("\tmodified=").append(new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.ROOT)
            .format(new Date(f.getLastModifiedTime())));
        String where = openLocation(f);
        if (where != null) sb.append("\topen=").append(where);
        return sb.toString();
    }

    private String openLocation(DomainFile f) {
        List<String> where = new ArrayList<>();
        for (McpEnvironment.OpenProgram op : env.openPrograms()) {
            if (op.program.getDomainFile().getPathname().equals(f.getPathname())) {
                where.add(op.location());
            }
        }
        return where.isEmpty() ? null : String.join(",", where);
    }

    private static Pattern filterPattern(String filter) {
        if (filter == null || filter.isBlank()) return null;
        String f = filter.trim();
        if (f.contains("*") || f.contains("?")) {
            StringBuilder re = new StringBuilder("(?i)");
            for (char ch : f.toCharArray()) {
                if (ch == '*') re.append(".*");
                else if (ch == '?') re.append('.');
                else re.append(Pattern.quote(String.valueOf(ch)));
            }
            return Pattern.compile(re.toString());
        }
        return Pattern.compile("(?i).*" + Pattern.quote(f) + ".*");
    }

    private static boolean matches(Pattern p, String path) {
        if (p == null) return true;
        if (p.matcher(path).matches()) return true;
        int slash = path.lastIndexOf('/', path.length() - 2);
        return p.matcher(path.substring(slash + 1)).matches();
    }

    // ------------------------------------------------------------------
    // Program info and lifecycle
    // ------------------------------------------------------------------

    private String programInfo(Program p) {
        String openIn = openLocation(p.getDomainFile()); // outside the Swing thread (see openPrograms)
        return McpSupport.onSwing(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("Name: ").append(p.getName()).append('\n');
            sb.append("Project path: ").append(p.getDomainFile().getPathname()).append('\n');
            sb.append("Language: ").append(p.getLanguageID()).append(" (")
                .append(p.getLanguage().getLanguageDescription().getDescription()).append(")\n");
            sb.append("Compiler spec: ").append(p.getCompilerSpec().getCompilerSpecID()).append('\n');
            sb.append("Processor: ").append(p.getLanguage().getProcessor()).append(", ")
                .append(p.getLanguage().isBigEndian() ? "big" : "little").append(" endian, ")
                .append(p.getDefaultPointerSize() * 8).append("-bit pointers\n");
            sb.append("Image base: ").append(p.getImageBase()).append('\n');
            Address min = p.getMinAddress();
            Address max = p.getMaxAddress();
            sb.append("Address range: ").append(min).append(" - ").append(max).append('\n');
            long initialized = 0;
            long total = 0;
            for (MemoryBlock b : p.getMemory().getBlocks()) {
                total += b.getSize();
                if (b.isInitialized()) initialized += b.getSize();
            }
            sb.append("Memory: ").append(p.getMemory().getBlocks().length).append(" blocks, ")
                .append(total).append(" bytes (").append(initialized).append(" initialized)\n");
            sb.append("Executable format: ").append(p.getExecutableFormat()).append('\n');
            sb.append("Executable path: ").append(p.getExecutablePath()).append('\n');
            if (p.getExecutableMD5() != null) sb.append("MD5: ").append(p.getExecutableMD5()).append('\n');
            if (p.getExecutableSHA256() != null) sb.append("SHA256: ").append(p.getExecutableSHA256()).append('\n');
            sb.append("Created: ").append(p.getCreationDate()).append('\n');
            sb.append("Functions: ").append(p.getFunctionManager().getFunctionCount()).append('\n');
            sb.append("Symbols: ").append(p.getSymbolTable().getNumSymbols()).append('\n');
            sb.append("Analysis: ").append(AnalysisTools.analysisState(p)).append('\n');
            sb.append("Unsaved changes: ").append(p.isChanged()).append('\n');
            sb.append("Read-only: ").append(p.getDomainFile().isReadOnly()).append('\n');
            sb.append("Open in: ").append(openIn);
            return sb.toString();
        });
    }

    private DomainFile projectFile(String path) {
        if (path == null || path.isBlank()) throw McpSupport.fail("path is required");
        DomainFile f = requireProject().getProjectData().getFile(path.trim());
        if (f == null) throw McpSupport.fail("Project file not found: " + path);
        return f;
    }

    private String openProgram(String path, String mode, boolean newWindow) throws Exception {
        DomainFile file = projectFile(path);
        if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) {
            throw McpSupport.fail(path + " is not a program (" + file.getContentType() + ")");
        }
        String m = mode == null || mode.isBlank() ? "background" : mode.trim().toLowerCase(Locale.ROOT);
        switch (m) {
            case "background": {
                Program p = env.openBackground(file, TaskMonitor.DUMMY);
                env.setPreferredProgram(p);
                return "Opened " + file.getPathname() + " in the background (current program)";
            }
            case "tool": {
                if (env.isHeadless()) throw McpSupport.fail("mode=tool is not available in headless mode");
                PluginTool tool = newWindow ? null : env.activeProgramTool();
                if (tool != null) {
                    ProgramManager pm = tool.getService(ProgramManager.class);
                    Program p = McpSupport.onSwing(() -> pm.openProgram(file));
                    if (p == null) throw McpSupport.fail("CodeBrowser could not open " + path);
                    env.setPreferredProgram(p);
                    return "Opened " + file.getPathname() + " in " + tool.getName();
                }
                ToolServices services = requireProject().getToolServices();
                List<PluginTool> before = env.runningTools();
                PluginTool launched = McpSupport.onSwing(() -> {
                    if (newWindow) {
                        // launchDefaultTool/launchTool honour the "Default Tool Launch Mode"
                        // preference and may reuse a running tool; Workspace.runTool always
                        // starts a new instance.
                        ghidra.framework.model.ToolTemplate template = services.getDefaultToolTemplate(file);
                        if (template == null) throw McpSupport.fail("No default tool for " + path);
                        PluginTool fresh = requireProject().getToolManager().getActiveWorkspace().runTool(template);
                        ProgramManager pm = fresh == null ? null : fresh.getService(ProgramManager.class);
                        if (pm == null || pm.openProgram(file) == null) {
                            throw McpSupport.fail("The new " + template.getName() + " could not open " + path);
                        }
                        return fresh;
                    }
                    return services.launchDefaultTool(List.of(file));
                });
                if (launched == null) throw McpSupport.fail("Could not launch the default tool for " + path);
                boolean reused = before.contains(launched);
                return "Opened " + file.getPathname() + " in " + (reused ? "the existing " : "a new ")
                    + launched.getName() + (reused ? " (Default Tool Launch Mode reuses running tools; "
                        + "pass new_window=true for a separate window)" : "");
            }
            default:
                throw McpSupport.fail("mode must be \"background\" or \"tool\"");
        }
    }

    private String closeProgram(Program program, boolean save, boolean discard) throws Exception {
        String path = program.getDomainFile().getPathname();
        boolean changed = program.isChanged();
        if (changed && !save && !discard) {
            throw McpSupport.fail(path + " has unsaved changes; pass save=true or discard=true");
        }
        if (changed && save) saveOne(program);
        boolean closedSomewhere = false;
        for (McpEnvironment.OpenProgram op : env.openPrograms()) {
            if (op.program != program || op.tool == null) continue;
            ProgramManager pm = op.tool.getService(ProgramManager.class);
            boolean closed = McpSupport.onSwing(() -> pm.closeProgram(program, true));
            if (!closed) throw McpSupport.fail("The CodeBrowser refused to close " + path);
            closedSomewhere = true;
        }
        if (env.releaseBackground(program)) closedSomewhere = true;
        if (!closedSomewhere) {
            throw McpSupport.fail(path + " is not open in a window or by the server "
                + "(e.g. the headless script's program); nothing was closed");
        }
        return "Closed " + path + (changed ? (save ? " (saved)" : " (changes discarded)") : "");
    }

    private void saveOne(Program program) throws Exception {
        DomainFile df = program.getDomainFile();
        if (df.isReadOnly() || !df.canSave()) {
            throw McpSupport.fail("Cannot save " + df.getPathname()
                + ": it is read-only (e.g. opened with -readOnly, or not checked out)");
        }
        try {
            df.save(TaskMonitor.DUMMY);
        }
        catch (java.io.IOException e) {
            throw McpSupport.fail("Cannot save " + df.getPathname() + ": " + e.getMessage());
        }
    }

    private String save(String selector, boolean all) throws Exception {
        if (all) {
            List<String> saved = new ArrayList<>();
            List<String> failed = new ArrayList<>();
            for (McpEnvironment.OpenProgram op : env.openPrograms()) {
                if (!op.program.isChanged()) continue;
                try {
                    saveOne(op.program);
                    saved.add(op.program.getDomainFile().getPathname());
                }
                catch (Exception e) {
                    failed.add(op.program.getDomainFile().getPathname() + ": " + e.getMessage());
                }
            }
            StringBuilder sb = new StringBuilder();
            sb.append(saved.isEmpty() ? "No programs with unsaved changes were saved"
                : "Saved: " + String.join(", ", saved));
            if (!failed.isEmpty()) sb.append("\nFailed:\n  ").append(String.join("\n  ", failed));
            if (!failed.isEmpty()) throw McpSupport.fail(sb.toString());
            return sb.toString();
        }
        Program p = McpSupport.program(env, selector);
        if (!p.isChanged()) return p.getDomainFile().getPathname() + ": no unsaved changes";
        saveOne(p);
        return "Saved " + p.getDomainFile().getPathname();
    }

    private String importFile(McpServer.Args a) throws Exception {
        Project project = requireProject();
        File file = new File(a.str("file_path"));
        if (!file.isFile()) throw McpSupport.fail("File not found: " + file);
        String folderPath = a.str("folder");
        if (folderPath == null || folderPath.isBlank()) folderPath = "/";
        ensureFolder(folderPath);
        ProgramLoader.Builder b = ProgramLoader.builder()
            .source(file)
            .project(project)
            .projectFolderPath(folderPath)
            .log(new MessageLog())
            .monitor(TaskMonitor.DUMMY);
        String name = a.str("name");
        if (name != null && !name.isBlank()) b.name(name.trim());
        String language = a.str("language");
        if (language != null && !language.isBlank()) b.language(language.trim());
        String compiler = a.str("compiler");
        if (compiler != null && !compiler.isBlank()) b.compiler(compiler.trim());
        String loader = a.str("loader");
        if (loader != null && !loader.isBlank()) b.loaders(McpSupport.loader(loader).getClass());
        String base = a.str("base_address");
        if (base != null && !base.isBlank()) {
            String v = base.trim();
            b.addLoaderArg("-loader-baseAddr", v.startsWith("0x") || v.startsWith("0X") ? v.substring(2) : v);
        }
        MessageLog log = new MessageLog();
        b.log(log);
        Object consumer = this;
        List<String> imported = new ArrayList<>();
        try (LoadResults<Program> results = b.load()) {
            results.save(TaskMonitor.DUMMY);
            for (Loaded<Program> loaded : results) {
                imported.add(loaded.getProjectFolderPath() + (loaded.getProjectFolderPath().endsWith("/") ? "" : "/")
                    + loaded.getName());
            }
            Program primary = results.getPrimaryDomainObject(consumer);
            String primaryPath = primary.getDomainFile().getPathname();
            String language1 = primary.getLanguageID() + " / " + primary.getCompilerSpec().getCompilerSpecID();
            String format = primary.getExecutableFormat();
            primary.release(consumer);
            StringBuilder sb = new StringBuilder();
            sb.append("Imported ").append(file.getName()).append(" as ").append(primaryPath)
                .append("\nFormat: ").append(format).append("\nLanguage: ").append(language1);
            if (imported.size() > 1) sb.append("\nAll imported files: ").append(String.join(", ", imported));
            if (a.bool("open")) {
                DomainFile df = project.getProjectData().getFile(primaryPath);
                Program p = env.openBackground(df, TaskMonitor.DUMMY);
                env.setPreferredProgram(p);
                sb.append("\nOpened in the background (current program). Run analyze_program to analyze it.");
            }
            String messages = log.toString().trim();
            if (!messages.isEmpty()) sb.append("\nLoader messages:\n").append(messages);
            return sb.toString();
        }
    }

    private DomainFolder ensureFolder(String path) throws Exception {
        DomainFolder f = requireProject().getProjectData().getRootFolder();
        for (String part : path.split("/")) {
            if (part.isEmpty()) continue;
            DomainFolder next = f.getFolder(part);
            f = next != null ? next : f.createFolder(part);
        }
        return f;
    }

    private String createFolder(String path) throws Exception {
        if (path == null || path.isBlank() || !path.trim().startsWith("/")) {
            throw McpSupport.fail("Folder path must start with '/'");
        }
        DomainFolder f = ensureFolder(path.trim());
        return "Folder ready: " + f.getPathname();
    }

    private Object item(String path) {
        ProjectData data = requireProject().getProjectData();
        String p = path == null ? "" : path.trim();
        if (p.length() > 1 && p.endsWith("/")) p = p.substring(0, p.length() - 1);
        DomainFile f = data.getFile(p);
        if (f != null) return f;
        DomainFolder folder = data.getFolder(p);
        if (folder != null) return folder;
        throw McpSupport.fail("Project file or folder not found: " + path);
    }

    private static void requireNotOpen(DomainFile f) {
        if (f.isOpen() || f.isBusy()) {
            throw McpSupport.fail(f.getPathname() + " is open; close it first (close_program)");
        }
    }

    private String renameItem(String path, String newName) throws Exception {
        if (newName == null || newName.isBlank() || newName.contains("/")) {
            throw McpSupport.fail("new_name must be a plain name");
        }
        Object it = item(path);
        if (it instanceof DomainFile) {
            requireNotOpen((DomainFile) it);
            DomainFile renamed = ((DomainFile) it).setName(newName.trim());
            return "Renamed to " + renamed.getPathname();
        }
        DomainFolder folder = (DomainFolder) it;
        if (folder.getParent() == null) throw McpSupport.fail("Cannot rename the root folder");
        DomainFolder renamed = folder.setName(newName.trim());
        return "Renamed to " + renamed.getPathname();
    }

    private String moveItem(String path, String destination) throws Exception {
        DomainFolder dest = folder(destination);
        Object it = item(path);
        if (it instanceof DomainFile) {
            requireNotOpen((DomainFile) it);
            DomainFile moved = ((DomainFile) it).moveTo(dest);
            return "Moved to " + moved.getPathname();
        }
        DomainFolder folder = (DomainFolder) it;
        if (folder.getParent() == null) throw McpSupport.fail("Cannot move the root folder");
        DomainFolder moved = folder.moveTo(dest);
        return "Moved to " + moved.getPathname();
    }

    private String deleteItem(String path, boolean confirm) throws Exception {
        if (!confirm) throw McpSupport.fail("Deletion is permanent; pass confirm=true to delete " + path);
        Object it = item(path);
        if (it instanceof DomainFile) {
            DomainFile f = (DomainFile) it;
            requireNotOpen(f);
            String p = f.getPathname();
            f.delete();
            return "Deleted " + p;
        }
        DomainFolder folder = (DomainFolder) it;
        if (folder.getParent() == null) throw McpSupport.fail("Cannot delete the root folder");
        if (folder.getFiles().length > 0 || folder.getFolders().length > 0) {
            throw McpSupport.fail("Folder " + folder.getPathname() + " is not empty");
        }
        String p = folder.getPathname();
        folder.delete();
        return "Deleted folder " + p;
    }

    // ------------------------------------------------------------------
    // Project switching (GUI, via the project window's file actions)
    // ------------------------------------------------------------------

    private String recentProjects() {
        ProjectManager pm = frontEnd().getProjectManager();
        StringBuilder sb = new StringBuilder();
        Project active = env.project();
        for (ProjectLocator loc : pm.getRecentProjects()) {
            sb.append(loc.getMarkerFile());
            if (active != null && loc.equals(active.getProjectLocator())) sb.append(" (active)");
            sb.append('\n');
        }
        return sb.length() == 0 ? "(no recent projects)" : sb.toString().trim();
    }

    private FrontEndTool frontEnd() {
        FrontEndTool fe = AppInfo.getFrontEndTool();
        if (fe == null) throw McpSupport.fail("The Ghidra project window is not available");
        return fe;
    }

    private void requireFrontEndOwner() {
        if (!McpRuntime.ownerSummary().contains(GhidraMCPServerPlugin.class.getSimpleName())) {
            throw McpSupport.fail("Switching projects closes every CodeBrowser and would stop this server. "
                + "Enable GhidraMCPServerPlugin in the project window (File > Configure) first.");
        }
    }

    /** Saves or discards unsaved changes as requested, then closes programs held by the server. */
    private void prepareProjectClose(boolean save, boolean discard) throws Exception {
        List<String> dirty = new ArrayList<>();
        for (McpEnvironment.OpenProgram op : env.openPrograms()) {
            if (op.program.isChanged()) dirty.add(op.program.getDomainFile().getPathname());
        }
        if (!dirty.isEmpty() && !save && !discard) {
            throw McpSupport.fail("Unsaved changes in: " + String.join(", ", dirty)
                + "; pass save=true or discard=true");
        }
        for (McpEnvironment.OpenProgram op : env.openPrograms()) {
            if (!op.program.isChanged()) continue;
            if (save) {
                saveOne(op.program);
            }
            else if (op.tool != null) {
                ProgramManager pm = op.tool.getService(ProgramManager.class);
                McpSupport.onSwing(() -> pm.closeProgram(op.program, true));
            }
        }
        env.releaseAll();
        // With several windows of the same tool (e.g. two CodeBrowsers) whose configuration
        // changed, Ghidra asks in a modal dialog which one to save, which would block this
        // request. Keep the change on the first window only.
        McpSupport.onSwing(() -> {
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (PluginTool t : env.runningTools()) {
                if (t.hasConfigChanged() && !seen.add(t.getToolName())) t.setConfigChanged(false);
            }
            return null;
        });
    }

    private Object fileActionManager() throws Exception {
        for (Plugin p : frontEnd().getManagedPlugins()) {
            if (p.getClass().getName().equals("ghidra.framework.main.FrontEndPlugin")) {
                Method m = p.getClass().getDeclaredMethod("getFileActionManager");
                m.setAccessible(true);
                return m.invoke(p);
            }
        }
        throw McpSupport.fail("Ghidra's project window plugin was not found");
    }

    private boolean invokeFileAction(String method, Class<?> type, Object arg) throws Exception {
        Object fam = fileActionManager();
        Method m = fam.getClass().getDeclaredMethod(method, type);
        m.setAccessible(true);
        Object r = McpSupport.onSwing(() -> m.invoke(fam, arg));
        return Boolean.TRUE.equals(r);
    }

    private static ProjectLocator locator(String path) {
        if (path == null || path.isBlank()) throw McpSupport.fail("path is required");
        File f = new File(path.trim());
        String name = f.getName();
        if (name.endsWith(ProjectLocator.getProjectExtension())) {
            name = name.substring(0, name.length() - ProjectLocator.getProjectExtension().length());
        }
        File dir = f.getParentFile();
        if (dir == null) throw McpSupport.fail("Project path must include a directory: " + path);
        return new ProjectLocator(dir.getAbsolutePath(), name);
    }

    private String openProject(String path, boolean save, boolean discard) throws Exception {
        requireFrontEndOwner();
        ProjectLocator loc = locator(path);
        if (!loc.getMarkerFile().exists()) {
            throw McpSupport.fail("Project not found: " + loc.getMarkerFile());
        }
        Project active = env.project();
        if (active != null && active.getProjectLocator().equals(loc)) {
            return "Project " + loc.getName() + " is already open";
        }
        if (active != null) {
            prepareProjectClose(save, discard);
            if (!invokeFileAction("closeProject", boolean.class, false)) {
                throw McpSupport.fail("Ghidra did not close project " + active.getName());
            }
        }
        if (!invokeFileAction("openProject", ProjectLocator.class, loc)) {
            throw McpSupport.fail("Ghidra could not open project " + loc.getMarkerFile());
        }
        Project now = env.project();
        return "Opened project " + (now == null ? loc.getName() : now.getName() + " at "
            + now.getProjectLocator().getMarkerFile());
    }

    private String closeProject(boolean save, boolean discard) throws Exception {
        requireFrontEndOwner();
        Project active = env.project();
        if (active == null) return "No project is open";
        String name = active.getName();
        prepareProjectClose(save, discard);
        if (!invokeFileAction("closeProject", boolean.class, false)) {
            throw McpSupport.fail("Ghidra did not close project " + name);
        }
        return "Closed project " + name;
    }

    private String createProject(String directory, String name, boolean save, boolean discard)
            throws Exception {
        requireFrontEndOwner();
        if (name == null || name.isBlank() || name.contains("/")) {
            throw McpSupport.fail("name must be a plain project name");
        }
        File dir = new File(directory);
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw McpSupport.fail("Cannot create directory " + dir);
        }
        ProjectLocator loc = new ProjectLocator(dir.getAbsolutePath(), name.trim());
        ProjectManager pm = frontEnd().getProjectManager();
        if (pm.projectExists(loc)) throw McpSupport.fail("Project already exists: " + loc.getMarkerFile());
        Project active = env.project();
        if (active != null) {
            prepareProjectClose(save, discard);
            if (!invokeFileAction("closeProject", boolean.class, false)) {
                throw McpSupport.fail("Ghidra did not close project " + active.getName());
            }
        }
        Project created = McpSupport.onSwing(() -> pm.createProject(loc, null, false));
        McpSupport.onSwing(() -> {
            created.close();
            return null;
        });
        if (!invokeFileAction("openProject", ProjectLocator.class, loc)) {
            throw McpSupport.fail("Created " + loc.getMarkerFile() + " but could not open it");
        }
        return "Created and opened project " + loc.getMarkerFile();
    }
}
