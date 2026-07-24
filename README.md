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
  This matches Ghidra's distinction between symbols and `Function` objects,
  which are the objects accepted by the decompiler.
- ARM/Thumb-aware `disassemble_code` with `auto`, `arm`, and `thumb` modes.
  Existing instructions are preserved, and defined data must be cleared
  explicitly before it can be converted to code.
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

## Multiple open programs

When several programs are open in the same Ghidra tool, every tool that reads or
modifies a program accepts an optional `program` argument to select which one to
act on. Discover the open programs with `list_open_programs` (the focused one is
marked `(current)`), then pass a name or project path, e.g.
`list_methods(program="firmware.sb")`. Leaving `program` empty keeps the previous
behavior and uses the currently focused program, so existing usage is
unaffected. GUI-context tools such as `get_current_address` intentionally report
the focused Code Browser state and do not take a program selector.

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure `Server Host` and `Server Port` in Ghidra with
   `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`. The default host is
   `127.0.0.1`; reload the plugin after changing either setting.

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source

Run `./build.sh`. It reads the installed Ghidra version from
`/opt/ghidra` (override with `GHIDRA_HOME`), copies the matching development
libraries into `lib/`, runs the parser tests, and creates
`target/GhidraMCP-1.0-SNAPSHOT.zip`.

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
