[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/siemens-mobile-hacks/GhidraMCP)](https://github.com/siemens-mobile-hacks/GhidraMCP/releases)

# GhidraMCP

Ghidra plugin that lets AI agents (Claude Code, Codex and other MCP clients)
work in your Ghidra project.

Based on [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) by [LaurieWired](https://github.com/LaurieWired) ❤️

## Battle tested

We use GhidraMCP to reverse engineer Siemens mobile phone firmware.

## Install

1. Download the zip from [Releases](https://github.com/siemens-mobile-hacks/GhidraMCP/releases)
   and install it with `File` → `Install Extensions`. Restart Ghidra.
2. In the project window, enable `GhidraMCPServerPlugin` in `File` → `Configure` → `Developer`.
3. Add the server to your client:

```
claude mcp add --scope user --transport http ghidra http://127.0.0.1:8080/mcp
codex mcp add ghidra --url http://127.0.0.1:8080/mcp
```

Headless:

```
analyzeHeadless <projectDir> <projectName> -process <file> -postScript StartGhidraMcpServer.java
```

## Tools

Tools work on the current program. Pass `program` to pick another open one.

### Project

- `get_project` — project info
- `list_project_files` — list files
- `create_project_folder` — create a folder
- `rename_project_file` — rename a file or folder
- `move_project_file` — move a file or folder
- `delete_project_file` — delete a file or folder
- `list_recent_projects` — recent projects (GUI)
- `open_project` — open a project (GUI)
- `close_project` — close the project (GUI)
- `create_project` — create a project (GUI)

### Programs

- `list_open_programs` — open programs
- `get_current_program` — current program
- `get_program_info` — processor, memory, format
- `open_program` — open a program
- `close_program` — close a program
- `save_program` — save a program
- `import_file` — import a file (File → Import File)
- `add_to_program` — add a file as a memory block (File → Add To Program)

### Analysis

- `analyze_program` — run auto-analysis
- `get_analysis_status` — analysis progress
- `cancel_analysis` — stop analysis
- `list_analyzers` — list analyzers
- `set_analyzer_options` — configure analyzers

### Functions

- `list_functions` — list functions
- `get_function` — function details
- `get_current_function` — function under the cursor
- `get_current_address` — address under the cursor
- `get_adjacent_function` — next or previous function
- `decompile_function` — C code
- `disassemble_function` — assembly
- `create_function` — create a function
- `delete_function` — delete a function
- `rename_function` — rename a function
- `batch_rename_functions` — rename many functions
- `set_function_prototype` — set the signature
- `set_function_comment` — set the comment
- `list_function_variables` — list variables
- `update_variable` — rename or retype a variable

### Code

- `disassemble_code` — disassemble bytes (ARM/Thumb)
- `get_listing` — listing of an address range
- `get_xrefs_to` — references to an address
- `get_xrefs_from` — references from an address
- `get_callers` — callers
- `get_callees` — callees
- `get_call_graph` — call graph
- `get_data_flow` — where a value comes from or goes
- `search_scalars` — find a constant
- `create_instruction_pattern` — pattern from instructions
- `search_instruction_pattern` — find a pattern

### Symbols and comments

- `list_symbols` — list symbols
- `list_namespaces` — list namespaces
- `list_imports` — list imports
- `list_exports` — list exports
- `create_label` — create a label
- `rename_symbol` — rename a symbol
- `delete_symbol` — delete a label
- `set_primary_symbol` — set the primary label
- `get_comments` — read comments
- `set_comment` — set a comment
- `batch_set_comments` — set many comments

### Data

- `list_data_items` — list data
- `get_data_at` — data at an address
- `list_strings` — list strings
- `apply_data_type` — apply a type
- `define_data_batch` — define many data items
- `update_data` — change data
- `clear_data` — clear data

### Data types

- `list_data_types` — list types
- `get_data_type` — type details
- `create_struct` — create a structure
- `create_union` — create a union
- `create_enum` — create an enum
- `create_typedef` — create a typedef
- `parse_c_types` — add types from C code
- `add_struct_field` — add a field
- `update_struct_field` — change a field
- `delete_struct_field` — delete a field
- `update_enum` — change an enum
- `delete_data_type` — delete a type

### Memory

- `list_segments` — memory map
- `read_bytes` — read bytes
- `write_bytes` — write bytes
- `search_memory` — search memory

### Scripts

- `list_scripts` — list scripts
- `run_script` — run a script

### Server

- `get_server_info` — server info
- `shutdown_ghidra` — exit Ghidra

## Build

```
./build.sh && ./install.sh
```

## License

[Apache License 2.0](LICENSE)
