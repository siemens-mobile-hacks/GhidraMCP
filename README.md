[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports
- Work with multiple binaries open in one Ghidra tool (target each by name)

## Differences from upstream

Compared with the [original GhidraMCP](https://github.com/LaurieWired/GhidraMCP),
this fork adds:

- Support for Ghidra 12.1.2 and a `build.sh` helper that collects the required
  libraries from a local Ghidra installation before building the extension.
- An optional `program` selector for every program-scoped MCP tool, allowing
  several binaries open in one Ghidra instance to be queried and modified
  without switching the focused Code Browser tab.
- Program discovery through `list_open_programs` and `get_current_program`.
- Native function creation through `create_function`. A label such as `LAB_*`
  is not treated as a function automatically: an instruction must exist at the
  requested entry point, and creation is rejected inside another function.
  Pass `disassemble_if_needed=true` to disassemble an undefined entry point and
  create the function in one MCP call.
  This matches Ghidra's distinction between symbols and `Function` objects,
  which are the objects accepted by the decompiler.
- ARM/Thumb-aware `disassemble_code` with `auto`, `arm`, and `thumb` modes.
  Existing instructions are preserved, and explicitly defined data must be
  cleared before it can be converted to code. Ghidra's one-byte `undefined`
  data units, including those created for raw firmware imports, are treated as
  disassemblable bytes and do not trigger the defined-data overlap guard. A
  successful response is returned only after the transaction completes and the
  instruction is confirmed in the listing.
- Bit-accurate instruction pattern generation and search through
  `create_instruction_pattern` and `search_instruction_pattern`. Patterns can
  mask all operands, scalar/address operand classes, or selected operands by
  zero-based instruction/operand index. They preserve partial-byte masks
  emitted by Ghidra's Sleigh engine and search undefined as well as
  disassembled bytes in loaded memory.
- Data-type tools backed by Ghidra's native `DataTypeParser` and `CParser`:
  inspect, create, and apply structures (including self-references and explicit
  field offsets), unions, enums, typedefs, pointers, arrays, bit fields, and C
  declarations. Types use native Ghidra category paths and can subsequently be
  used in data definitions, structure fields, and function prototypes.
- Function-prototype updates through Ghidra's `FunctionSignatureParser`, with
  optional `calling_convention` and `source_type` controls. Calls made by older
  clients without a calling convention preserve the function's current ABI.
- Data-management tools for safely clearing and defining data, reading bytes,
  querying data items, and creating labels. Instructions are never cleared
  implicitly, offcut data is handled by its complete range, and mutations are
  verified before their transactions are committed.
- Atomic batch operations for defining data, renaming functions, and setting
  comments: a failed item rolls back the whole batch instead of leaving a
  partially updated program.
- Configurable HTTP bind host and port under `GhidraMCP HTTP Server` tool
  options. The default is `127.0.0.1:8080`, so the plugin is not exposed on
  external interfaces unless explicitly configured.
- A built-in MCP endpoint at `/mcp` (Streamable HTTP transport): MCP clients
  connect to Ghidra directly, no Python bridge. Requests that carry a
  non-loopback browser `Origin` header are rejected to block DNS-rebinding and
  cross-site requests from web pages.
- One server per Ghidra process that works everywhere: from the project window
  (no CodeBrowser needed), across all CodeBrowser windows, and headless. See
  [Where the server runs](#where-the-server-runs).
- Project and program management, auto-analysis control, call graphs, data
  flow, scalar search, symbol/data/comment/type editing, memory search and
  patching, scripts, MCP prompts and resources. See [Tool groups](#tool-groups).

## Where the server runs

The MCP server is shared by everything in one Ghidra process and is started by
whichever of these comes first:

- **Project window** — enable `GhidraMCPServerPlugin` once in the project window
  (`File` -> `Configure` -> plug icon -> `Developer` -> `GhidraMCPServerPlugin`).
  The server then runs for the whole session, without any CodeBrowser, and
  project tools (`open_project`, `close_project`, `create_project`) become usable.
- **CodeBrowser** — `GhidraMCPPlugin` (as before) keeps the server alive while a
  CodeBrowser window is open.
- **Headless** — run the bundled script:
  ```
  analyzeHeadless <projectDir> <projectName> -process <file> -noanalysis \
      -postScript StartGhidraMcpServer.java [port] [host]
  ```
  It blocks until `shutdown_ghidra` is called (or the process is stopped).

Programs are resolved globally: an empty `program` argument means the program
opened last through MCP (until you focus another window), else the program of the
focused CodeBrowser; a name or project path selects any program open in any
window or opened by the server in the background (`open_program`).

## Tool groups

| Group | Tools |
|---|---|
| Server | `get_server_info`, `shutdown_ghidra` |
| Project | `get_project`, `list_project_files`, `create_project_folder`, `rename_project_file`, `move_project_file`, `delete_project_file`, `list_recent_projects`, `open_project`, `close_project`, `create_project` |
| Programs | `list_open_programs`, `get_current_program`, `get_program_info`, `open_program` (background or CodeBrowser, `new_window`), `close_program`, `save_program`, `import_file` |
| Analysis | `analyze_program` (blocking with timeout or background), `get_analysis_status`, `cancel_analysis`, `list_analyzers`, `set_analyzer_options` |
| Functions | `list_functions` (filters), `get_function`, `get_adjacent_function`, `create_function`, `delete_function`, `rename_function(_by_address)` (namespaces via `A::B::f`), `set_function_prototype`, `list_function_variables`, `update_variable`, `set_function_comment`, `batch_rename_functions` |
| Decompiler | `decompile_function(_by_address)` (cached per program, timeout, line ranges, optional P-code), `disassemble_function` (paging, bytes), `disassemble_code` |
| Symbols & data | `list_symbols`, `rename_symbol`, `delete_symbol`, `set_primary_symbol`, `create_label`, `list_data_items` (filters), `get_data_at`, `define_data(_batch)`, `apply_data_type`, `clear_data`, `update_data`, `rename_data`, `list_strings` |
| Comments | `get_comments`, `set_comment` (pre, post, eol, plate, repeatable), `set_decompiler_comment`, `set_disassembly_comment`, `batch_set_comments` |
| Types | `list_data_types`, `get_data_type`, `create_struct/union/enum/typedef`, `parse_c_types`, `add_struct_field`, `update_struct_field`, `delete_struct_field`, `update_enum`, `delete_data_type` |
| Code analysis | `get_xrefs_to/from` (type filter), `get_function_xrefs`, `get_callers`, `get_callees`, `get_call_graph`, `get_data_flow` (decompiler P-code slices), `search_scalars` |
| Memory | `read_bytes` (hex, hexdump, base64, ascii), `write_bytes`, `search_memory` (bytes, strings, values), `search_instruction_pattern`, `create_instruction_pattern`, `get_listing`, `list_segments` |
| Scripts | `list_scripts`, `run_script` (by name or ad-hoc source) |

MCP prompts: `analyze_function`, `identify_vulnerabilities`,
`reverse_engineer_binary`, `recover_structures` (they embed the decompiled code
and call relations). MCP resources: `ghidra://<program>/info`,
`ghidra://<program>/function/<name-or-address>/decompile` and `/disassembly`
(URL-encode the program path, e.g. `ghidra://%2Ffirmware.bin/info`).

## Multiple open programs

When several programs are open in the same Ghidra tool, every tool that reads or
modifies a program accepts an optional `program` argument to select which one to
act on. Discover the open programs with `list_open_programs` (the focused one is
marked `(current)`), then pass a name or project path, e.g.
`list_methods(program="firmware.sb")`. Leaving `program` empty keeps the previous
behavior and uses the currently focused program, so existing usage is
unaffected. GUI-context tools such as `get_current_address` intentionally report
the focused Code Browser state and do not take a program selector.

## Instruction pattern search

`create_instruction_pattern` builds a pattern from one or more contiguous,
already-disassembled instructions. By default the pattern is exact. Masking can
be enabled for every operand (`mask_operands`), for all scalar or address
operands (`mask_scalars` / `mask_addresses`), or for individual operands with
`masked_operands`. Individual selectors use zero-based
`instruction_index:operand_index` notation; for example, `0:1` selects the
second operand of the first instruction.

```python
pattern = create_instruction_pattern(
    address="00123456",
    instruction_count=3,
    masked_operands=["0:1", "2:0"],
)
matches = search_instruction_pattern(pattern=pattern, limit=100)
```

The canonical pattern format uses exact hexadecimal bytes (`D8`), full-byte
wildcards (`??`), nibble wildcards (`A?` or `?5`), and Ghidra-compatible
bit-level masks (`[10..01..]`). `search_instruction_pattern` accepts all these
forms and optionally restricts matches with `start_address` and `end_address`.
It searches loaded, initialized memory directly, so matching bytes do not need
to have been disassembled first.

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)

## Ghidra
Build the extension (see [Building from Source](#building-from-source)) and run `./install.sh`, or import the zip manually:

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
   (CodeBrowser), and optionally enable `GhidraMCPServerPlugin` in the project
   window to run the server without a CodeBrowser (see above)
7. *Optional*: Configure `Server Host` and `Server Port` in Ghidra with
   `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`. The default host is
   `127.0.0.1`; reload the plugin after changing either setting.

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

The plugin itself is an MCP server: while Ghidra is running with the plugin
enabled, it serves MCP over Streamable HTTP at `http://127.0.0.1:8080/mcp`
(host and port follow the plugin options).

Examples for popular coding-agent CLIs (all use the Streamable HTTP URL above):

**Claude Code**

```
claude mcp add --transport http ghidra http://127.0.0.1:8080/mcp
```

**Codex CLI** — command, or the equivalent in `~/.codex/config.toml`:

```
codex mcp add ghidra --url http://127.0.0.1:8080/mcp
```

```toml
[mcp_servers.ghidra]
url = "http://127.0.0.1:8080/mcp"
```

**GitHub Copilot CLI** (stored in `~/.copilot/mcp-config.json`):

```
copilot mcp add --transport http ghidra http://127.0.0.1:8080/mcp
```

**Qwen Code** (stored in `~/.qwen/settings.json`):

```
qwen mcp add --transport http ghidra http://127.0.0.1:8080/mcp
```

**OpenCode** (add `--global` for all projects):

```
opencode mcp add ghidra --url http://127.0.0.1:8080/mcp
```

**Gemini CLI** — `~/.gemini/settings.json` (or `.gemini/settings.json` in a
project); note the key is `httpUrl` (`url` means SSE there):

```json
{ "mcpServers": { "ghidra": { "httpUrl": "http://127.0.0.1:8080/mcp" } } }
```

**Cursor CLI / Cursor** — `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a
project); the CLI shares the editor's configuration:

```json
{ "mcpServers": { "ghidra": { "url": "http://127.0.0.1:8080/mcp" } } }
```

Any other client that supports the Streamable HTTP transport is configured the
same way. Clients that can only launch stdio servers can use a generic adapter
such as `npx mcp-remote http://127.0.0.1:8080/mcp`.

Start Ghidra before the client connects. If the client started first, reconnect
it after Ghidra is up (in Claude Code: `/mcp` -> `ghidra` -> reconnect).

# Building from Source

Run `./build.sh`. It reads the installed Ghidra version from
`/opt/ghidra` (override with `GHIDRA_HOME`), copies the matching development
libraries into `lib/`, runs the unit tests, and creates
`target/GhidraMCP-1.0-SNAPSHOT.zip`.

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
- ghidra_scripts/StartGhidraMcpServer.java

`./install.sh` installs the built zip into the user's Ghidra settings
(`~/.config/ghidra/ghidra_<version>_<release>/Extensions`, the same place
`File` -> `Install Extensions` uses), keeping the last three previous versions in
`ExtensionBackups`. Restart Ghidra afterwards.

## End-to-end tests

`tests/e2e` exercises every tool against a real Ghidra:

```
tests/e2e/cycle.sh                 # stop the e2e server, rebuild, install, start headless (port 18080)
python3 tests/e2e/run_e2e.py       # all checks (headless)
python3 tests/e2e/run_e2e.py --url http://127.0.0.1:8080/mcp --mode gui   # against the GUI
python3 tests/e2e/run_e2e.py --mode gui --only gui_projects               # project switching (GUI)
```

The test binary (`tests/e2e/target.c`, compiled for x86-64 and ARM Thumb) and
the throw-away project live in `e2e-work/` (git-ignored); mutating checks only
touch that project.
