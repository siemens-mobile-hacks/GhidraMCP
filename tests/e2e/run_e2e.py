#!/usr/bin/env python3
"""End-to-end checks of every GhidraMCP tool against a live Ghidra.

Usage: run_e2e.py [--url URL] [--only GROUP[,GROUP]] [--mode headless|gui]

The target is tests/e2e/target.c compiled to /mcp_target (x86-64 ELF) and
/thumb.o (ARM Thumb) in the e2e project (see headless.sh). Mutating checks
only touch those test programs.
"""
import argparse
import re
import sys
import traceback

from mcp_client import Mcp

GROUPS = []


def group(name):
    def deco(fn):
        GROUPS.append((name, fn))
        return fn
    return deco


class Checker:
    def __init__(self, mcp, mode):
        self.mcp = mcp
        self.mode = mode
        self.passed = 0
        self.failed = []
        self.called = set()

    def call(self, tool, /, **args):
        self.called.add(tool)
        return self.mcp.call(tool, **args)

    def check(self, label, tool, args=None, expect=(), absent=(), error=False, regex=()):
        """Calls tool and verifies substrings/regexes; returns the text."""
        args = args or {}
        try:
            text, is_error = self.call(tool, **args)
        except Exception as e:  # transport/protocol failure
            self._fail(label, tool, args, f"exception: {e}")
            return ""
        problems = []
        if error is not None and is_error != error:
            problems.append(f"isError={is_error}, expected {error}")
        for s in expect:
            if s not in text:
                problems.append(f"missing {s!r}")
        for s in absent:
            if s in text:
                problems.append(f"unexpected {s!r}")
        for r in regex:
            if not re.search(r, text, re.M):
                problems.append(f"no match for /{r}/")
        if problems:
            self._fail(label, tool, args, "; ".join(problems) + "\n    --- output ---\n    "
                       + text[:1500].replace("\n", "\n    "))
        else:
            self.passed += 1
            print(f"  ok   {label}")
        return text

    def _fail(self, label, tool, args, why):
        self.failed.append(label)
        print(f"  FAIL {label}: {tool}({args})\n    {why}")


P = "/mcp_target"  # program selector used throughout


def fn_addr(c, name):
    """Entry address of a function, via list_functions."""
    text, _ = c.call("list_functions", program=P, name_regex="(^|::)" + re.escape(name) + "$")
    m = re.search(re.escape(name) + r" at ([0-9a-fA-F]+)", text)
    if not m:
        raise AssertionError(f"function {name} not found:\n{text}")
    return m.group(1)


def addr_of(text, name):
    m = re.search(re.escape(name) + r"\s*@\s*([0-9a-fA-Fx]+)", text)
    if not m:
        raise AssertionError(f"address of {name} not found in:\n{text}")
    return m.group(1)


# ---------------------------------------------------------------------------
# Legacy tools (regression after the core refactoring)
# ---------------------------------------------------------------------------

@group("legacy")
def legacy(c):
    c.check("list_open_programs", "list_open_programs", expect=["mcp_target"])
    c.check("get_current_program", "get_current_program",
            expect=["mcp_target"] if c.mode == "headless" else [], regex=[r"\t/\S+"])
    if c.mode == "headless":
        c.check("get_current_address (no window)", "get_current_address", expect=["No CodeBrowser"])
        c.check("get_current_function (no window)", "get_current_function", expect=["No CodeBrowser"])
    else:
        c.check("get_current_address (focused window)", "get_current_address", regex=[r"^[0-9a-f]{4,}$"])
        c.check("get_current_function (focused window)", "get_current_function",
                regex=[r"^(Function: \S+ at [0-9a-f]+|No function at current location)"])
    c.check("list_functions", "list_functions", {"program": P}, expect=["checksum at "])
    c.check("list_segments", "list_segments", {"program": P}, expect=[".text"])
    c.check("list_imports", "list_imports", {"program": P}, expect=["printf"])
    c.check("list_exports", "list_exports", {"program": P}, expect=["main"])
    c.check("list_namespaces", "list_namespaces", {"program": P})
    c.check("list_data_items", "list_data_items", {"program": P, "limit": 500}, expect=["g_counter"])
    c.check("list_functions name_contains", "list_functions", {"program": P, "name_contains": "add_num"},
            expect=["add_numbers at "])
    add = fn_addr(c, "add_numbers")
    chk = fn_addr(c, "checksum")
    c.check("list_strings", "list_strings", {"program": P, "filter": "banner"}, expect=["mcp-e2e-banner"])
    c.check("get_function by address", "get_function", {"program": P, "address": add},
            expect=["add_numbers"])
    c.check("decompile_function", "decompile_function", {"program": P, "name": "checksum"},
            expect=["checksum("])
    c.check("decompile_function by address", "decompile_function",
            {"program": P, "address": add}, expect=["add_numbers("])
    c.check("disassemble_function", "disassemble_function", {"program": P, "address": add},
            regex=[r"RET"])
    c.check("get_xrefs_to", "get_xrefs_to", {"program": P, "address": add}, expect=["main"])
    c.check("get_xrefs_from", "get_xrefs_from", {"program": P, "address": add})
    c.check("get_callers (was get_function_xrefs)", "get_callers", {"program": P, "name": "add_numbers"},
            expect=["main"])
    c.check("read_bytes", "read_bytes", {"program": P, "address": add, "length": 4})
    c.check("get_data_at g_counter", "get_data_at",
            {"program": P, "address": find_symbol_addr(c, "g_counter")}, expect=["g_counter"])
    c.check("list_data_types", "list_data_types", {"program": P, "query": "int"}, expect=["int"])
    c.check("get_data_type", "get_data_type", {"program": P, "name": "int"}, expect=["int"])
    c.check("create_instruction_pattern", "create_instruction_pattern",
            {"program": P, "address": add, "instruction_count": 2})
    c.check("search_instruction_pattern", "search_instruction_pattern",
            {"program": P, "pattern": "C3", "limit": 3}, regex=[r"[0-9a-f]{6,}"])

    # Mutations on the test program
    c.check("rename_function", "rename_function",
            {"program": P, "old_name": "checksum", "new_name": "checksum_e2e"}, expect=["Renamed"])
    c.check("rename_function by address", "rename_function",
            {"program": P, "address": chk, "new_name": "checksum"}, expect=["Renamed function"])
    c.check("set_function_prototype", "set_function_prototype",
            {"program": P, "function_address": add, "prototype": "int add_numbers(int a, int b)"},
            expect=["successfully"])
    c.check("update_variable rename (was rename_variable)", "update_variable",
            {"program": P, "function_name": "add_numbers", "variable": "a", "new_name": "lhs"})
    c.check("update_variable type (was set_local_variable_type)", "update_variable",
            {"program": P, "function_address": chk, "variable": "param_1", "new_type": "char *"})
    c.check("set_comment pre", "set_comment",
            {"program": P, "address": add, "comment": "e2e pre", "comment_type": "pre"}, expect=["Set pre"])
    c.check("set_comment eol", "set_comment",
            {"program": P, "address": add, "comment": "e2e eol"}, expect=["Set eol"])
    c.check("batch_set_comments", "batch_set_comments",
            {"program": P, "comments": [{"address": add, "comment": "batch"}]})
    c.check("batch_rename_functions", "batch_rename_functions",
            {"program": P, "renames": [{"address": chk, "new_name": "checksum"}]})
    g = find_symbol_addr(c, "g_counter")
    c.check("rename_symbol (was rename_data)", "rename_symbol",
            {"program": P, "address": g, "old_name": "g_counter", "new_name": "g_counter"})
    c.check("create_label", "create_label", {"program": P, "address": g, "name": "e2e_label"})
    c.check("create_enum", "create_enum", {"program": P, "name": "E2EColor",
            "values": [{"name": "RED", "value": 0}, {"name": "GREEN", "value": 1}]}, absent=["Error"])
    c.check("create_struct", "create_struct", {"program": P, "name": "E2EPoint",
            "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "int"}]}, absent=["Error"])
    c.check("create_union", "create_union", {"program": P, "name": "E2EUnion",
            "fields": [{"name": "i", "type": "int"}, {"name": "f", "type": "float"}]}, absent=["Error"])
    c.check("create_typedef", "create_typedef", {"program": P, "name": "e2e_u32", "base_type": "uint"},
            absent=["Error"])
    c.check("parse_c_types", "parse_c_types", {"program": P, "code": "typedef struct { int a; } E2EParsed;"},
            absent=["Error"])
    origin = find_symbol_addr(c, "g_origin")
    c.check("apply_data_type struct", "apply_data_type",
            {"program": P, "address": origin, "data_type": "E2EPoint"}, absent=["Error", "Failed"])
    c.check("apply_data_type", "apply_data_type", {"program": P, "address": g, "data_type": "uint"},
            absent=["Error", "Failed"])
    c.check("clear_data", "clear_data", {"program": P, "address": g}, absent=["Error"])
    c.check("apply_data_type dword", "apply_data_type", {"program": P, "address": g, "data_type": "dword"},
            absent=["Error"])
    c.check("clear before batch", "clear_data", {"program": P, "address": g}, absent=["Error"])
    c.check("define_data_batch", "define_data_batch",
            {"program": P, "items": [{"address": g, "data_type": "dword", "label": "g_counter"}]},
            absent=["Error", "Rolled back"])
    c.check("create_function (existing)", "create_function", {"program": P, "address": add},
            expect=["already"])
    c.check("disassemble_code (existing)", "disassemble_code", {"program": P, "address": add},
            expect=["already defined"])


def find_symbol_addr(c, name):
    text, err = c.call("list_symbols", program=P, name_regex="^" + re.escape(name) + "$")
    if not err:
        m = re.search(re.escape(name) + r" @ ([0-9a-fA-F]+)", text)
        if m:
            return m.group(1)
    text, _ = c.call("list_data_items", program=P, limit=1000)
    for line in text.splitlines():
        m = re.match(r"([0-9a-fA-F]+): (\S+) =", line)
        if m and m.group(2) == name:
            return m.group(1)
    return fn_addr(c, name)


# ---------------------------------------------------------------------------
# Server, project and program lifecycle (plan stages 1-3)
# ---------------------------------------------------------------------------

import os
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
THUMB_O = os.path.join(ROOT, "e2e-work", "bin", "thumb.o")


@group("server")
def server(c):
    mode = "headless" if c.mode == "headless" else "GUI"
    c.check("get_server_info", "get_server_info", expect=["GhidraMCP", "Mode: " + mode, "Project:"])
    c.check("list_open_programs shows location", "list_open_programs",
            regex=[r"mcp_target\t/mcp_target\t\[[^\]]+\]"])


@group("project")
def project(c):
    c.check("get_project", "get_project", expect=["Project: ", "Files: "])
    c.check("list_project_files", "list_project_files", expect=["/mcp_target", "type=Program"])
    c.check("list_project_files filter", "list_project_files", {"filter": "thumb*"},
            expect=["/thumb.o"], absent=["/mcp_target"])
    c.check("list_project_files content_type", "list_project_files",
            {"content_type": "Program", "recursive": True}, expect=["/thumb.o", "/mcp_target"])
    c.check("list_project_files bad folder", "list_project_files", {"folder": "/nope"}, error=True,
            expect=["not found"])
    c.check("get_program_info", "get_program_info", {"program": P},
            expect=["Language: x86:LE:64", "Functions: ", "Executable format: Executable and Linking Format",
                    "Analysis: analyzed"])
    c.check("create_project_folder", "create_project_folder", {"path": "/e2e/sub"},
            expect=["Folder ready: /e2e/sub"])
    c.check("create_project_folder bad", "create_project_folder", {"path": "e2e"}, error=True)
    # clean leftovers from an earlier run
    c.call("delete_project_file", path="/e2e/thumb_import", confirm=True)
    c.call("delete_project_file", path="/thumb_renamed", confirm=True)
    c.check("import_file", "import_file",
            {"file_path": THUMB_O, "folder": "/e2e", "name": "thumb_import"},
            expect=["Imported thumb.o as /e2e/thumb_import", "ARM", "Opened in the background"])
    c.check("imported program is current", "get_current_program", expect=["thumb_import"])
    c.call("delete_project_file", path="/e2e/blob_raw", confirm=True)
    c.check("import_file raw binary loader", "import_file",
            {"file_path": THUMB_O, "folder": "/e2e", "name": "blob_raw", "loader": "Raw Binary",
             "language": "ARM:LE:32:Cortex", "base_address": "0x8000000", "block_name": "flash",
             "file_offset": 16, "length": 64, "open": False},
            expect=["Imported thumb.o as /e2e/blob_raw", "Format: Raw Binary", "ARM:LE:32:Cortex"])
    c.call("open_program", path="/e2e/blob_raw")
    c.check("raw import block name/offset/length", "list_segments", {"program": "/e2e/blob_raw"},
            regex=[r"^flash: 0?8000000 - 0?800003f  size=0x40 "])
    c.call("close_program", program="/e2e/blob_raw")
    c.check("import_file unknown loader", "import_file", {"file_path": THUMB_O, "loader": "Nope"},
            error=True, expect=["Unknown loader", "Raw Binary"])
    c.check("delete raw import", "delete_project_file", {"path": "/e2e/blob_raw", "confirm": True})
    c.check("import_file missing", "import_file", {"file_path": "/nonexistent.bin"}, error=True,
            expect=["File not found"])
    c.check("imported program not analyzed", "get_program_info", {"program": "/e2e/thumb_import"},
            expect=["Analysis: not analyzed"])
    c.check("open_program mode=tool headless", "open_program",
            {"path": "/thumb.o", "mode": "tool"}, error=(c.mode == "headless"))
    if c.mode == "headless":
        c.check("open_program background", "open_program", {"path": "/thumb.o"},
                expect=["Opened /thumb.o in the background"])
    c.check("list_open_programs includes background", "list_open_programs",
            expect=["/thumb.o\t[", "/e2e/thumb_import\t[background]"])
    c.check("close_program /thumb.o", "close_program", {"program": "/thumb.o"}, expect=["Closed /thumb.o"])
    c.check("open_program not a file", "open_program", {"path": "/nope"}, error=True)


@group("analysis")
def analysis(c):
    T = "/e2e/thumb_import"
    c.check("list_analyzers", "list_analyzers", {"program": T, "filter": "decompiler"},
            regex=[r"^\[[x ]\] Decompiler Parameter ID"])
    c.check("list_analyzers options", "list_analyzers",
            {"program": T, "filter": "Decompiler Parameter ID", "include_options": True},
            expect=["Decompiler Parameter ID."])
    c.check("set_analyzer_options", "set_analyzer_options",
            {"program": T, "options": [{"name": "Decompiler Parameter ID", "value": "true"}]},
            expect=["Decompiler Parameter ID = true"])
    c.check("set_analyzer_options unknown", "set_analyzer_options",
            {"program": T, "options": [{"name": "No Such Analyzer", "value": "true"}]}, error=True,
            expect=["Unknown analysis option"])
    c.check("set_analyzer_options bad bool", "set_analyzer_options",
            {"program": T, "options": [{"name": "Decompiler Parameter ID", "value": "maybe"}]}, error=True)
    c.check("analyze_program wait", "analyze_program", {"program": T},
            expect=["Last MCP run: completed", "Functions: "])
    c.check("status analyzed", "get_analysis_status", {"program": T},
            expect=["State: analyzed", "completed"])
    c.check("program info analyzed", "get_program_info", {"program": T}, expect=["Analysis: analyzed"])
    c.check("functions found by analysis", "list_functions", {"program": T}, expect=["add_numbers"])
    c.check("analyze_program background", "analyze_program", {"program": T, "wait": False},
            expect=["started in the background"])
    for _ in range(120):
        text, _ = c.call("get_analysis_status", program=T)
        if "analysis running" not in text:
            break
        time.sleep(0.5)
    c.check("background analysis finished", "get_analysis_status", {"program": T},
            expect=["completed"], absent=["analysis running"])
    c.check("cancel_analysis idle", "cancel_analysis", {"program": T}, expect=["No analysis is running"])


@group("lifecycle")
def lifecycle(c):
    T = "/e2e/thumb_import"
    c.check("save_program", "save_program", {"program": T}, expect=["Saved /e2e/thumb_import"])
    c.check("save_program unchanged", "save_program", {"program": T}, expect=["no unsaved changes"])
    c.check("set comment to dirty", "set_comment",
            {"program": T, "address": "00010000", "comment": "dirty"})
    c.check("close_program refuses dirty", "close_program", {"program": T}, error=True,
            expect=["unsaved changes"])
    # may partially fail when the headless script's (locked) program is dirty
    c.check("save_program all", "save_program", {"all": True}, expect=["Saved: ", "/e2e/thumb_import"],
            error=None)
    c.check("rename open file refused", "rename_project_file", {"path": T, "new_name": "x"}, error=True,
            expect=["is open"])
    c.check("close_program", "close_program", {"program": T}, expect=["Closed /e2e/thumb_import"])
    c.check("rename_project_file", "rename_project_file", {"path": T, "new_name": "thumb_renamed"},
            expect=["Renamed to /e2e/thumb_renamed"])
    c.check("move_project_file", "move_project_file", {"path": "/e2e/thumb_renamed", "destination": "/"},
            expect=["Moved to /thumb_renamed"])
    c.check("reopen moved program keeps comment", "open_program", {"path": "/thumb_renamed"},
            expect=["Opened"])
    c.check("comment persisted after save", "get_program_info", {"program": "/thumb_renamed"},
            expect=["Analysis: analyzed"])
    c.check("close reopened", "close_program", {"program": "/thumb_renamed"}, expect=["Closed"])
    c.check("delete needs confirm", "delete_project_file", {"path": "/thumb_renamed"}, error=True,
            expect=["confirm=true"])
    c.check("delete_project_file", "delete_project_file", {"path": "/thumb_renamed", "confirm": True},
            expect=["Deleted /thumb_renamed"])
    c.check("delete non-empty folder refused", "delete_project_file", {"path": "/e2e", "confirm": True},
            error=True, expect=["not empty"])
    c.check("delete folder", "delete_project_file", {"path": "/e2e/sub", "confirm": True},
            expect=["Deleted folder /e2e/sub"])
    c.check("delete folder 2", "delete_project_file", {"path": "/e2e", "confirm": True},
            expect=["Deleted folder /e2e"])
    c.check("dirty read-only program", "set_comment",
            {"program": P, "address": "00401000", "comment": "dirty"})
    if c.mode == "headless":
        # The headless script's own transaction keeps its program locked.
        c.check("save script program refused", "save_program", {"program": P}, error=True,
                expect=["Cannot save", "/mcp_target"])


# ---------------------------------------------------------------------------
# Decompiler and disassembly (plan stage 9)
# ---------------------------------------------------------------------------

@group("decompiler")
def decompiler(c):
    c.check("decompile by name", "decompile_function", {"program": P, "name": "distance2"},
            expect=["distance2("])
    c.check("decompile cached (same output)", "decompile_function", {"program": P, "name": "distance2"},
            expect=["distance2("])
    c.check("decompile line range", "decompile_function",
            {"program": P, "name": "main", "start_line": 2, "max_lines": 3},
            regex=[r"^\s*2: ", r"-- lines 2-4 of \d+; next start_line 5 --"])
    c.check("decompile start past end", "decompile_function",
            {"program": P, "name": "main", "start_line": 100000}, error=True, expect=["past the end"])
    c.check("style parameter removed", "decompile_function",
            {"program": P, "name": "add_numbers", "style": "normalize"}, expect=["add_numbers("])
    c.check("decompile include_pcode", "decompile_function",
            {"program": P, "name": "add_numbers", "include_pcode": True}, expect=["--- P-code", "RETURN"])
    c.check("decompile unknown function", "decompile_function", {"program": P, "name": "nope_fn"},
            error=True, expect=["Function not found"])
    c.check("decompile needs name or address", "decompile_function", {"program": P}, error=True)
    chk = fn_addr(c, "checksum")
    inside = format(int(chk, 16) + 4, "x")
    c.check("decompile by inner address", "decompile_function",
            {"program": P, "address": inside}, expect=["checksum("])
    c.check("decompile by address timeout param", "decompile_function",
            {"program": P, "address": chk, "timeout": 5}, expect=["checksum("])
    c.check("disassemble paging", "disassemble_function",
            {"program": P, "address": chk, "offset": 1, "limit": 2, "show_bytes": True},
            regex=[r"^[0-9a-f]+: [0-9a-f]+ +\S", r"-- 2-3 of \d+"])
    c.check("disassemble full", "disassemble_function", {"program": P, "address": chk}, regex=[r"RET"],
            absent=["-- "])
    c.check("legacy HTTP decompile uses cache", "get_server_info", expect=["GhidraMCP"])


# ---------------------------------------------------------------------------
# Functions (plan stage 4)
# ---------------------------------------------------------------------------

@group("functions")
def functions(c):
    add = fn_addr(c, "add_numbers")
    dist = fn_addr(c, "distance2")
    c.check("list_functions name_contains", "list_functions", {"program": P, "name_contains": "NUMB"},
            expect=["add_numbers at "], absent=["main at"])
    c.check("list_functions regex", "list_functions", {"program": P, "name_regex": "^(main|checksum)$"},
            expect=["main at", "checksum at"], absent=["add_numbers"])
    c.check("list_functions bad regex", "list_functions", {"program": P, "name_regex": "("}, error=True,
            expect=["Invalid regular expression"])
    c.check("list_functions address range", "list_functions",
            {"program": P, "start_address": add, "end_address": add}, expect=["add_numbers at " ],
            regex=[r"\A[^\n]*add_numbers at [0-9a-f]+\Z"])
    c.check("list_functions paging footer", "list_functions", {"program": P, "limit": 2},
            regex=[r"-- 1-2 of \d+; next offset 2 --"])
    c.check("get_function by name", "get_function", {"program": P, "name": "add_numbers"},
            expect=["Function: add_numbers at", "Signature: ", "Calling convention:", "Parameters:",
                    "Body: ", "Callers: 1"])
    c.check("get_function by inner address", "get_function",
            {"program": P, "address": format(int(add, 16) + 1, "x")}, expect=["Function: add_numbers"])
    c.check("get_function missing args", "get_function", {"program": P}, error=True)
    c.check("get_adjacent_function next", "get_adjacent_function", {"program": P, "address": add},
            regex=[r"Next function: \S+ at [0-9a-f]+"], absent=["add_numbers at"])
    c.check("get_adjacent_function prev", "get_adjacent_function",
            {"program": P, "address": add, "direction": "prev"}, regex=[r"Previous function: "])
    c.check("get_adjacent_function bad dir", "get_adjacent_function",
            {"program": P, "address": add, "direction": "up"}, error=True)
    # namespace rename (FQN) and back
    c.check("rename into namespace", "rename_function",
            {"program": P, "address": dist, "new_name": "Geo::Math::distance2"},
            expect=["-> Geo::Math::distance2"])
    c.check("FQN lookup", "get_function", {"program": P, "name": "Geo::Math::distance2"},
            expect=["Function: Geo::Math::distance2"])
    c.check("bare lookup of namespaced", "decompile_function", {"program": P, "name": "distance2"},
            expect=["distance2("])
    c.check("list_functions namespace filter", "list_functions", {"program": P, "namespace": "Geo::Math"},
            expect=["Geo::Math::distance2 at"], absent=["main at"])
    c.check("rename back to global", "rename_function",
            {"program": P, "old_name": "Geo::Math::distance2", "new_name": "::distance2"},
            expect=["-> distance2"])
    # variables
    c.check("set prototype for vars", "set_function_prototype",
            {"program": P, "function_address": dist, "prototype": "int distance2(int x, int y)"})
    c.check("list_function_variables", "list_function_variables", {"program": P, "address": dist},
            expect=["param 0: int x @", "param 1: int y @"])
    c.check("list_function_variables decompiler", "list_function_variables",
            {"program": P, "address": dist, "include_decompiler": True}, expect=["decompiler param: int x"],
            absent=["param_1"])
    c.check("update_variable rename+type", "update_variable",
            {"program": P, "function_address": dist, "variable": "x", "new_name": "px", "new_type": "uint"},
            expect=["Updated parameter x", "uint px"])
    c.check("update_variable verify", "get_function", {"program": P, "address": dist},
            expect=["uint px @"])
    c.check("update_variable bad type", "update_variable",
            {"program": P, "function_address": dist, "variable": "px", "new_type": "nosuchtype_t"},
            error=True, expect=["data type"])
    c.check("update_variable missing", "update_variable",
            {"program": P, "function_address": dist, "variable": "zzz", "new_name": "q"}, error=True,
            expect=["not found"])
    c.check("update_variable nothing", "update_variable",
            {"program": P, "function_address": dist, "variable": "px"}, error=True)
    c.check("set_function_comment", "set_function_comment",
            {"program": P, "address": dist, "comment": "squared distance to origin"},
            expect=["Set comment of distance2"])
    c.check("function comment visible", "get_function", {"program": P, "address": dist},
            expect=["Comment: squared distance to origin"])
    c.check("function comment in decompiler", "decompile_function",
            {"program": P, "address": dist}, expect=["squared distance to origin"])
    c.check("clear function comment", "set_function_comment",
            {"program": P, "address": dist, "comment": ""}, expect=["Cleared"])
    # delete and recreate
    c.check("delete_function", "delete_function", {"program": P, "address": dist},
            expect=["Deleted function distance2"])
    c.check("deleted function gone", "get_function", {"program": P, "address": dist}, error=True)
    c.check("recreate function", "create_function", {"program": P, "address": dist, "name": "distance2"},
            absent=["Error", "Failed"])
    c.check("recreated", "get_function", {"program": P, "name": "distance2"}, expect=["Function: distance2"])


# ---------------------------------------------------------------------------
# Symbols, data, strings, comments (plan stage 5)
# ---------------------------------------------------------------------------

@group("symbols")
def symbols(c):
    g = find_symbol_addr(c, "g_counter")
    add = fn_addr(c, "add_numbers")
    c.check("list_symbols type=function", "list_symbols", {"program": P, "type": "function", "limit": 1000},
            expect=["add_numbers @ " + add + " [function"], absent=["[external"])
    c.check("list_symbols external", "list_symbols", {"program": P, "type": "external"},
            expect=["printf"])
    c.check("list_symbols name_regex", "list_symbols", {"program": P, "name_regex": "^g_(counter|origin)$"},
            expect=["g_counter @", "g_origin @"])
    c.check("list_symbols at address", "list_symbols", {"program": P, "address": g}, expect=["g_counter @ "])
    c.check("list_symbols source imported", "list_symbols",
            {"program": P, "source": "imported", "name_contains": "banner"}, expect=["g_banner"])
    c.check("list_symbols bad source", "list_symbols", {"program": P, "source": "magic"}, error=True)
    c.check("create second label", "create_label", {"program": P, "address": g, "name": "e2e_alias"})
    c.check("rename_symbol ambiguous", "rename_symbol", {"program": P, "address": g, "new_name": "x"},
            error=True, expect=["Several symbols"])
    c.check("rename_symbol", "rename_symbol",
            {"program": P, "address": g, "old_name": "e2e_alias", "new_name": "Vars::e2e_alias2"},
            expect=["-> Vars::e2e_alias2"])
    c.check("set_primary_symbol", "set_primary_symbol",
            {"program": P, "address": g, "name": "Vars::e2e_alias2"}, expect=["is now the primary"])
    c.check("primary visible", "list_symbols", {"program": P, "address": g},
            regex=[r"Vars::e2e_alias2 @ \S+ \[[^\]]*primary\]"])
    c.check("set_primary back", "set_primary_symbol", {"program": P, "address": g, "name": "g_counter"})
    c.check("delete_symbol", "delete_symbol", {"program": P, "address": g, "name": "Vars::e2e_alias2"},
            expect=["Deleted symbol Vars::e2e_alias2"])
    c.call("delete_symbol", program=P, address=g, name="e2e_label")
    c.check("delete_symbol function refused", "delete_symbol", {"program": P, "address": add}, error=True,
            expect=["use delete_function"])
    c.check("list_data_items type filter", "list_data_items", {"program": P, "type": "string"},
            expect=["g_banner", "[string"], absent=["[dword]", "[uint]"])
    c.check("list_data_items name filter", "list_data_items", {"program": P, "name_contains": "COUNTER"},
            regex=[r"g_counter = \S+ \[\w+\]"])
    c.check("list_data_items range", "list_data_items",
            {"program": P, "start_address": g, "end_address": g}, regex=[r"\A[0-9a-f]+: g_counter"])
    c.check("update_data", "update_data",
            {"program": P, "address": g, "data_type": "uint", "label": "g_counter2", "comment": "e2e data"},
            expect=["type uint", "label g_counter2", "Now: uint g_counter2"])
    c.check("update_data comment visible", "get_comments", {"program": P, "address": g},
            expect=["eol: e2e data"])
    c.check("update_data restore", "update_data",
            {"program": P, "address": g, "data_type": "dword", "label": "g_counter", "comment": ""},
            expect=["comment cleared"])
    c.check("update_data refuses code", "update_data", {"program": P, "address": add, "data_type": "dword"},
            error=True, expect=["Instructions exist"])
    c.check("update_data nothing", "update_data", {"program": P, "address": g}, error=True)
    c.check("list_strings", "list_strings", {"program": P, "filter": "BANNER"},
            regex=[r'"mcp-e2e-banner" \(14, \w+, g_banner\)'])
    for ct in ["pre", "post", "eol", "plate", "repeatable"]:
        c.check("set_comment " + ct, "set_comment",
                {"program": P, "address": add, "comment": "e2e " + ct, "comment_type": ct},
                expect=["Set " + ct + " comment"])
    c.check("get_comments all types", "get_comments", {"program": P, "address": add},
            expect=["pre: e2e pre", "post: e2e post", "eol: e2e eol", "plate: e2e plate",
                    "repeatable: e2e repeatable"])
    c.check("pre comment in decompiler", "decompile_function", {"program": P, "name": "add_numbers"},
            expect=["e2e pre"])
    c.check("get_comments range", "get_comments",
            {"program": P, "address": add, "end_address": format(int(add, 16) + 64, "x")},
            expect=[add + " plate: e2e plate"])
    c.check("set_comment bad type", "set_comment",
            {"program": P, "address": add, "comment": "x", "comment_type": "side"}, error=True)
    c.check("clear comment", "set_comment", {"program": P, "address": add, "comment": "", "comment_type": "post"},
            expect=["Cleared post"])
    c.check("cleared", "get_comments", {"program": P, "address": add}, absent=["post:"])


# ---------------------------------------------------------------------------
# Code analysis (plan stage 8)
# ---------------------------------------------------------------------------

@group("codeanalysis")
def codeanalysis(c):
    add = fn_addr(c, "add_numbers")
    g = find_symbol_addr(c, "g_counter")
    c.check("xrefs_to CALL", "get_xrefs_to", {"program": P, "address": add, "ref_type": "CALL"},
            regex=[r"From [0-9a-f]+ in main \[UNCONDITIONAL_CALL\]"])
    c.check("xrefs_to READ none", "get_xrefs_to", {"program": P, "address": add, "ref_type": "READ"},
            expect=["(none)"])
    t = c.check("xrefs_to g_counter READ", "get_xrefs_to", {"program": P, "address": g, "ref_type": "READ"},
                regex=[r"From [0-9a-f]+ in add_numbers \[READ\]"])
    read_at = re.search(r"From ([0-9a-f]+) in add_numbers", t).group(1) if "add_numbers" in t else add
    c.check("xrefs_from DATA", "get_xrefs_from", {"program": P, "address": read_at, "ref_type": "DATA"},
            regex=[r"To [0-9a-f]+ \(data g_counter"])
    t = c.check("get_callers", "get_callers", {"program": P, "name": "add_numbers"},
                regex=[r"main @ [0-9a-f]+ \(calls at [0-9a-f]+\)"])
    c.check("get_callees main", "get_callees", {"program": P, "name": "main"},
            expect=["add_numbers @", "checksum @", "distance2 @", "printf"])
    c.check("get_callees leaf", "get_callees", {"program": P, "name": "add_numbers"}, expect=["calls no functions"])
    c.check("call graph tree", "get_call_graph", {"program": P, "name": "main", "max_depth": 2},
            regex=[r"^main @ ", r"^  add_numbers @ ", r"^  \S*printf @ [0-9a-f]+ \[thunk\]",
                   r"^    <EXTERNAL>::printf @ \S+ \[(thunk|external)\]"])
    c.check("call graph edges", "get_call_graph", {"program": P, "name": "main", "format": "edges"},
            regex=[r"^main -> add_numbers @ [0-9a-f]+", r"\(\d+ functions, \d+ edges\)"])
    c.check("call graph callers", "get_call_graph",
            {"program": P, "name": "add_numbers", "direction": "callers"}, regex=[r"^  main @ "])
    c.check("call graph truncation", "get_call_graph", {"program": P, "name": "main", "max_nodes": 2},
            expect=["truncated at max_nodes 2"])
    c.check("call graph bad direction", "get_call_graph", {"program": P, "name": "main", "direction": "up"},
            error=True)
    c.check("data flow by variable", "get_data_flow",
            {"program": P, "function_name": "checksum", "variable": "param_1"},
            expect=["Forward data flow of variable param_1 in checksum", "LOAD"])
    c.check("data flow by address", "get_data_flow", {"program": P, "address": read_at},
            expect=["Forward data flow of values at " + read_at, "RETURN"])
    c.check("data flow backward", "get_data_flow",
            {"program": P, "address": read_at, "direction": "backward"}, expect=["Backward data flow"])
    c.check("data flow register", "get_data_flow",
            {"program": P, "function_name": "add_numbers", "address": add, "register": "EDI"},
            regex=[r"Forward data flow of EDI at "])
    c.check("data flow unknown var", "get_data_flow",
            {"program": P, "function_name": "checksum", "variable": "nope"}, error=True, expect=["not found"])
    c.check("search_scalars in main", "search_scalars", {"program": P, "value": "7", "in_function": "main"},
            regex=[r"0x7.*\[operand \d\] in main"])
    c.check("search_scalars to_function", "search_scalars",
            {"program": P, "value": "0x7", "to_function": "distance2"}, regex=[r"-> distance2 at [0-9a-f]+"])
    c.check("search_scalars to_function miss", "search_scalars",
            {"program": P, "value": "7", "in_function": "main", "to_function": "checksum"}, expect=["(none)"])
    c.check("search_scalars bad value", "search_scalars", {"program": P, "value": "seven"}, error=True)


# ---------------------------------------------------------------------------
# Type editing (plan stage 6)
# ---------------------------------------------------------------------------

@group("types")
def types(c):
    for n in ["E2ETyp", "E2EUni", "E2EMode", "E2EDel"]:
        c.call("delete_data_type", program=P, name=n, force=True)
    c.check("create struct", "create_struct", {"program": P, "name": "E2ETyp",
            "fields": [{"name": "a", "type": "int"}, {"name": "b", "type": "int"}]}, absent=["Error"])
    c.check("add_struct_field append", "add_struct_field",
            {"program": P, "struct": "E2ETyp", "field_name": "c", "field_type": "short", "comment": "tail"},
            expect=["+0x8 short c // tail", "(size 10)"])
    c.check("add_struct_field occupied", "add_struct_field",
            {"program": P, "struct": "E2ETyp", "field_name": "x", "field_type": "int", "offset": 4},
            error=True, expect=["occupied"])
    c.check("add_struct_field insert", "add_struct_field",
            {"program": P, "struct": "E2ETyp", "field_name": "ins", "field_type": "char", "offset": 4,
             "insert": True}, expect=["+0x4 char ins", "+0x5 int b"])
    c.check("add_struct_field bitfield", "add_struct_field",
            {"program": P, "struct": "E2ETyp", "field_name": "flag", "field_type": "uint", "bit_size": 3},
            expect=["flag (bit field)"])
    c.check("update_struct_field", "update_struct_field",
            {"program": P, "struct": "E2ETyp", "field_name": "b", "new_name": "bb", "new_type": "uint",
             "new_comment": "renamed"}, expect=["+0x5 uint bb // renamed"])
    c.check("update_struct_field by offset", "update_struct_field",
            {"program": P, "struct": "E2ETyp", "field_offset": 0, "new_name": "first"}, expect=["+0x0 int first"])
    c.check("update_struct_field missing", "update_struct_field",
            {"program": P, "struct": "E2ETyp", "field_name": "zz", "new_name": "q"}, error=True)
    t = c.check("delete_struct_field keep layout", "delete_struct_field",
                {"program": P, "struct": "E2ETyp", "field_name": "ins"}, expect=["Deleted field ins",
                "+0x5 uint bb"], absent=["char ins"])
    size_before = re.search(r"\(size (\d+)\)", t).group(1) if "(size" in t else "?"
    c.check("delete_struct_field shift", "delete_struct_field",
            {"program": P, "struct": "E2ETyp", "field_name": "c", "keep_layout": False},
            regex=[r"\(size (?!" + size_before + r"\))\d+\)"])
    c.check("get_data_type shows edits", "get_data_type", {"program": P, "name": "E2ETyp"},
            expect=["first", "bb"])
    c.check("create union", "create_union", {"program": P, "name": "E2EUni",
            "fields": [{"name": "i", "type": "int"}]}, absent=["Error"])
    c.check("union add field", "add_struct_field",
            {"program": P, "struct": "E2EUni", "field_name": "d", "field_type": "double"},
            expect=["union", "double d", "(size 8)"])
    c.check("union retype", "update_struct_field",
            {"program": P, "struct": "E2EUni", "field_name": "i", "new_type": "longlong"}, expect=["longlong i"])
    c.check("not a composite", "add_struct_field",
            {"program": P, "struct": "int", "field_name": "x", "field_type": "int"}, error=True)
    c.check("create enum", "create_enum", {"program": P, "name": "E2EMode",
            "values": [{"name": "OFF", "value": 0}, {"name": "ON", "value": 1}]}, absent=["Error"])
    c.check("update_enum", "update_enum", {"program": P, "name": "E2EMode",
            "add": [{"name": "AUTO", "value": 2}], "remove": ["OFF"], "rename": [{"old": "ON", "new": "ENABLED"}],
            "size": 1}, expect=["(size 1)", "ENABLED = 0x1", "AUTO = 0x2"], absent=["OFF"])
    c.check("update_enum duplicate", "update_enum",
            {"program": P, "name": "E2EMode", "add": [{"name": "AUTO", "value": 3}]}, error=True)
    c.check("update_enum nothing", "update_enum", {"program": P, "name": "E2EMode"}, error=True)
    c.check("create E2EDel", "create_struct", {"program": P, "name": "E2EDel",
            "fields": [{"name": "v", "type": "int"}, {"name": "w", "type": "int"}]}, absent=["Error"])
    origin = find_symbol_addr(c, "g_origin")
    c.check("apply E2EDel", "apply_data_type", {"program": P, "address": origin, "data_type": "E2EDel"},
            absent=["Error", "Failed"])
    c.check("delete used type refused", "delete_data_type", {"program": P, "name": "E2EDel"}, error=True,
            expect=["is in use", "data at " + origin])
    c.check("delete used type force", "delete_data_type", {"program": P, "name": "E2EDel", "force": True},
            expect=["Deleted /E2EDel"])
    c.check("deleted type gone", "get_data_type", {"program": P, "name": "E2EDel"}, absent=["v", "struct"])
    c.check("delete used builtin refused", "delete_data_type", {"program": P, "name": "int"}, error=True,
            expect=["is in use", "return type of"])
    c.check("delete type not in program", "delete_data_type", {"program": P, "name": "wchar16"}, error=True,
            expect=["built-in"])
    c.check("delete unused", "delete_data_type", {"program": P, "name": "E2EUni"}, expect=["Deleted /E2EUni"])


# ---------------------------------------------------------------------------
# Memory (plan stage 7)
# ---------------------------------------------------------------------------

@group("memory")
def memory(c):
    g = find_symbol_addr(c, "g_counter")
    add = fn_addr(c, "add_numbers")
    c.check("read hex", "read_bytes", {"program": P, "address": g, "length": 4}, expect=["44332211"])
    c.check("read hexdump", "read_bytes", {"program": P, "address": g, "length": 4, "format": "hexdump"},
            expect=[g + "  44 33 22 11", '|D3".|'])
    c.check("read base64", "read_bytes", {"program": P, "address": g, "length": 4, "format": "base64"},
            expect=["RDMiEQ=="])
    c.check("read ascii", "read_bytes", {"program": P, "address": g, "length": 4, "format": "ascii"},
            expect=['D3".'])
    c.check("read bad format", "read_bytes", {"program": P, "address": g, "length": 4, "format": "oct"},
            error=True)
    c.check("read too long", "read_bytes", {"program": P, "address": g, "length": 0}, error=True)
    c.check("search value", "search_memory", {"program": P, "query": "0x11223344", "kind": "value"},
            expect=[g + " [.data] g_counter"])
    c.check("search value big endian", "search_memory",
            {"program": P, "query": "0x44332211", "kind": "value", "endian": "big"}, expect=[g])
    c.check("search hex", "search_memory", {"program": P, "query": "44 33 22 11"}, expect=[g])
    c.check("search string", "search_memory", {"program": P, "query": "mcp-e2e-banner", "kind": "string"},
            expect=["g_banner"])
    c.check("search utf16 none", "search_memory", {"program": P, "query": "zq", "kind": "utf16le"},
            expect=["No matches"])
    c.check("search range limit", "search_memory",
            {"program": P, "query": "00", "start_address": g, "limit": 2}, expect=["more matches beyond limit 2"])
    c.check("search bad hex", "search_memory", {"program": P, "query": "abc"}, error=True)
    c.check("get_listing", "get_listing", {"program": P, "start_address": add, "max_units": 3},
            regex=[r"^add_numbers:", r"^  " + add + r"  [0-9a-f]+ +\S", r"stopped at max_units 3"])
    c.check("get_listing data", "get_listing", {"program": P, "start_address": g, "end_address": g},
            regex=[r"g_counter:\n  " + g + r"  44332211 +(dword|undefined4|uint) "])
    c.check("list_segments", "list_segments", {"program": P},
            regex=[r"^\.text: \S+ - \S+  size=0x[0-9a-f]+  r-x  ", r"^\.data: .* rw- "])
    c.check("write_bytes", "write_bytes", {"program": P, "address": g, "bytes": "aa bb cc dd"},
            expect=["Wrote 4 byte(s)", "aabbccdd"])
    c.check("written bytes read back", "read_bytes", {"program": P, "address": g, "length": 4},
            expect=["aabbccdd"])
    c.check("write_bytes base64 restore", "write_bytes",
            {"program": P, "address": g, "bytes": "RDMiEQ==", "format": "base64"}, expect=["44332211"])
    t, _ = c.call("read_bytes", program=P, address=add, length=4)
    orig = t.strip()
    c.check("write into code refused", "write_bytes", {"program": P, "address": add, "bytes": orig},
            error=True, expect=["clear_code=true"])
    c.check("write into code with clear", "write_bytes",
            {"program": P, "address": add, "bytes": orig, "clear_code": True}, expect=["overlapping code cleared"])
    c.check("re-disassemble", "disassemble_code", {"program": P, "address": add}, expect=["Disassembled"])
    c.check("function intact", "decompile_function", {"program": P, "name": "add_numbers"},
            expect=["add_numbers("])


# ---------------------------------------------------------------------------
# MCP prompts and resources (plan stage 10)
# ---------------------------------------------------------------------------

def rpc_check(c, label, method, params, predicate, expect_error=False):
    try:
        result = c.mcp.rpc(method, params)
        err = None
    except Exception as e:  # McpError carries the JSON-RPC error
        result, err = None, e
    ok = (err is not None) if expect_error else (err is None and predicate(result))
    if ok:
        c.passed += 1
        print(f"  ok   {label}")
    else:
        c.failed.append(label)
        print(f"  FAIL {label}: {method} {params}\n    {err or str(result)[:1200]}")
    return result


@group("prompts")
def prompts(c):
    init = c.mcp.initialize()
    caps = init["capabilities"]
    ok = "prompts" in caps and "resources" in caps
    c.passed += ok
    print(("  ok   " if ok else "  FAIL ") + "capabilities advertise prompts and resources")
    if not ok:
        c.failed.append("capabilities")
    rpc_check(c, "prompts/list", "prompts/list", {},
              lambda r: {"analyze_function", "identify_vulnerabilities", "reverse_engineer_binary",
                         "recover_structures"} <= {p["name"] for p in r["prompts"]})
    rpc_check(c, "analyze_function prompt", "prompts/get",
              {"name": "analyze_function", "arguments": {"name": "checksum", "program": P}},
              lambda r: "```c" in r["messages"][0]["content"]["text"]
              and "checksum(" in r["messages"][0]["content"]["text"]
              and "Callers: main" in r["messages"][0]["content"]["text"])
    rpc_check(c, "identify_vulnerabilities prompt", "prompts/get",
              {"name": "identify_vulnerabilities", "arguments": {"name": "main", "program": P}},
              lambda r: "buffer overflows" in r["messages"][0]["content"]["text"])
    rpc_check(c, "reverse_engineer_binary prompt", "prompts/get",
              {"name": "reverse_engineer_binary", "arguments": {"program": P}},
              lambda r: "Entry points:" in r["messages"][0]["content"]["text"])
    rpc_check(c, "recover_structures prompt", "prompts/get",
              {"name": "recover_structures", "arguments": {"name": "distance2", "program": P}},
              lambda r: "create_struct" in r["messages"][0]["content"]["text"])
    rpc_check(c, "prompt unknown function", "prompts/get",
              {"name": "analyze_function", "arguments": {"name": "nope_fn", "program": P}}, None,
              expect_error=True)
    rpc_check(c, "unknown prompt", "prompts/get", {"name": "nope"}, None, expect_error=True)
    rpc_check(c, "resources/list", "resources/list", {},
              lambda r: any(x["uri"] == "ghidra://%2Fmcp_target/info" for x in r["resources"]))
    rpc_check(c, "resources/templates/list", "resources/templates/list", {},
              lambda r: len(r["resourceTemplates"]) == 3)
    rpc_check(c, "read info", "resources/read", {"uri": "ghidra://%2Fmcp_target/info"},
              lambda r: "Language: x86:LE:64" in r["contents"][0]["text"])
    rpc_check(c, "read decompile", "resources/read",
              {"uri": "ghidra://%2Fmcp_target/function/checksum/decompile"},
              lambda r: "checksum(" in r["contents"][0]["text"] and r["contents"][0]["mimeType"] == "text/x-c")
    chk = fn_addr(c, "checksum")
    rpc_check(c, "read disassembly by address", "resources/read",
              {"uri": "ghidra://%2Fmcp_target/function/" + chk + "/disassembly"},
              lambda r: r["contents"][0]["text"].startswith(chk + ":"))
    rpc_check(c, "read unknown resource", "resources/read", {"uri": "ghidra://x/y"}, None, expect_error=True)


# ---------------------------------------------------------------------------
# Scripts (plan stage 11; shutdown_ghidra is exercised by cycle.sh)
# ---------------------------------------------------------------------------

E2E_SCRIPT = """
import ghidra.app.script.GhidraScript;
public class McpE2EScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("program=" + currentProgram.getName());
        println("arg0=" + getScriptArgs()[0]);
        createLabel(currentProgram.getImageBase(), "script_made_label", true);
    }
}
"""

LOOP_SCRIPT = """
import ghidra.app.script.GhidraScript;
public class McpLoopScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        while (true) { monitor.checkCancelled(); Thread.sleep(50); }
    }
}
"""


@group("scripts")
def scripts(c):
    c.check("list_scripts", "list_scripts", {"filter": "HelloWorld"}, expect=["HelloWorldScript.java"])
    c.check("list_scripts extension", "list_scripts", {"filter": "StartGhidraMcp"},
            expect=["StartGhidraMcpServer.java\tGhidraMCP"])
    c.check("run_script by name", "run_script", {"name": "HelloWorldScript.java", "program": P},
            expect=["completed", "Hello World"])
    c.check("run_script source", "run_script",
            {"source": E2E_SCRIPT, "args": ["xyz"], "program": P},
            expect=["completed", "program=mcp_target", "arg0=xyz"])
    c.check("script change visible", "list_symbols", {"program": P, "name_contains": "script_made_label"},
            expect=["script_made_label @"])
    c.check("temp script removed", "list_scripts", {"filter": "McpE2EScript"}, expect=["(none)"])
    c.check("run_script compile error", "run_script",
            {"source": "public class McpBad extends GhidraScript { void run() { nope } }", "program": P},
            error=True)
    c.check("run_script both", "run_script", {"name": "x.java", "source": "y"}, error=True,
            expect=["exactly one"])
    c.check("run_script missing", "run_script", {"name": "NoSuchScript.java"}, error=True,
            expect=["Script not found"])
    c.check("run_script timeout", "run_script",
            {"source": LOOP_SCRIPT, "timeout_seconds": 2, "program": P}, error=None,
            regex=[r"cancel"])


# ---------------------------------------------------------------------------
# Project switching (GUI only, plan stage 2b). Run explicitly: --only gui_projects
# ---------------------------------------------------------------------------

E2E_PROJECT = os.path.join(ROOT, "e2e-work", "project", "MCPTest.gpr")
CREATED_DIR = os.path.join(ROOT, "e2e-work", "created")


@group("gui_projects")
def gui_projects(c):
    if c.mode != "gui":
        print("  skip (GUI only)")
        return
    import shutil
    shutil.rmtree(CREATED_DIR, ignore_errors=True)
    c.check("list_recent_projects", "list_recent_projects", expect=["MCPTest.gpr (active)"])
    c.check("dirty program", "set_comment", {"program": P, "address": "00401000", "comment": "dirty"})
    c.check("close_project refuses dirty", "close_project", error=True, expect=["Unsaved changes", "/mcp_target"])
    c.check("close_project discard", "close_project", {"discard": True}, expect=["Closed project MCPTest"])
    c.check("no project", "get_project", error=True, expect=["No project is open"])
    c.check("server alive without project", "get_server_info", expect=["Project: (none)", "Tool windows: (none)"])
    c.check("create_project", "create_project", {"directory": CREATED_DIR, "name": "MCPCreated"},
            expect=["Created and opened project", "MCPCreated.gpr"])
    c.check("created project active", "get_project", expect=["Project: MCPCreated", "Files: 0"])
    c.check("import into created project", "import_file", {"file_path": THUMB_O},
            expect=["Imported thumb.o as /thumb.o"])
    c.check("create_project exists", "create_project", {"directory": CREATED_DIR, "name": "MCPCreated"},
            error=True, expect=["already exists"])
    c.check("open_project missing", "open_project", {"path": "/nonexistent/X.gpr"}, error=True,
            expect=["Project not found"])
    c.check("open_project back", "open_project", {"path": E2E_PROJECT}, expect=["Opened project MCPTest"])
    c.check("open_project same", "open_project", {"path": E2E_PROJECT}, expect=["already open"])
    c.check("recent lists both", "list_recent_projects", expect=["MCPTest.gpr (active)", "MCPCreated.gpr"])
    c.check("e2e project files", "list_project_files", expect=["/mcp_target", "/thumb.o"])
    c.check("dirty change was discarded", "open_program", {"path": "/mcp_target"}, expect=["Opened"])
    c.check("comment gone", "get_comments", {"program": P, "address": "00401000"}, absent=["dirty"])
    c.check("close", "close_program", {"program": P}, expect=["Closed"])


# ---------------------------------------------------------------------------
# Add To Program
# ---------------------------------------------------------------------------

BLOB = os.path.join(ROOT, "e2e-work", "bin", "blob.bin")


@group("addtoprogram")
def addtoprogram(c):
    with open(BLOB, "wb") as f:
        f.write(bytes(range(64)))
    t, _ = c.call("list_segments", program=P)
    if "e2e_blob" in t:
        print("  skip (blocks from an earlier run in this session)")
        return
    c.check("add raw file", "add_to_program",
            {"program": P, "file_path": BLOB, "address": "0x00700000", "block_name": "e2e_blob"},
            expect=["using Raw Binary", "e2e_blob: 00700000 - 0070003f  size=0x40"])
    c.check("added bytes", "read_bytes", {"program": P, "address": "00700000", "length": 8},
            expect=["0001020304050607"])
    c.check("block listed", "list_segments", {"program": P},
            regex=[r"^e2e_blob: 00700000 - 0070003f  size=0x40  "])
    c.check("part of file", "add_to_program",
            {"program": P, "file_path": BLOB, "address": "0x00700100", "block_name": "e2e_part",
             "file_offset": 16, "length": 8}, expect=["e2e_part: 00700100 - 00700107  size=0x8"])
    c.check("part bytes", "read_bytes", {"program": P, "address": "00700100", "length": 8},
            expect=["1011121314151617"])
    c.check("overlap refused", "add_to_program",
            {"program": P, "file_path": BLOB, "address": "0x00700020", "block_name": "e2e_clash"},
            error=True, expect=["overlaps e2e_blob", "overlay=true"])
    c.check("overlay", "add_to_program",
            {"program": P, "file_path": BLOB, "address": "0x00700000", "block_name": "e2e_ovl",
             "overlay": True}, expect=["overlay"])
    c.check("address required", "add_to_program", {"program": P, "file_path": BLOB}, error=True,
            expect=["address is required"])
    c.check("bad offset", "add_to_program",
            {"program": P, "file_path": BLOB, "address": "0x00710000", "file_offset": 100}, error=True)
    c.check("unknown loader", "add_to_program",
            {"program": P, "file_path": BLOB, "address": "0x00710000", "loader": "Nope"}, error=True,
            expect=["Unknown loader"])
    c.check("missing file", "add_to_program",
            {"program": P, "file_path": "/nonexistent.bin", "address": "0x00710000"}, error=True,
            expect=["File not found"])


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18080/mcp")
    ap.add_argument("--only", default="")
    ap.add_argument("--mode", default="headless", choices=["headless", "gui"])
    args = ap.parse_args()
    mcp = Mcp(args.url)
    mcp.initialize()
    c = Checker(mcp, args.mode)
    selected = set(filter(None, args.only.split(",")))
    for name, fn in GROUPS:
        if selected and name not in selected:
            continue
        print(f"[{name}]")
        try:
            fn(c)
        except Exception:
            c.failed.append(f"{name}: crashed")
            traceback.print_exc()
    tools = set(mcp.tools())
    untested = sorted(tools - c.called)
    print(f"\n{c.passed} passed, {len(c.failed)} failed; tools exposed {len(tools)}, "
          f"exercised {len(tools & c.called)}")
    if untested:
        print("not exercised: " + ", ".join(untested))
    for f in c.failed:
        print("  failed: " + f)
    return 1 if c.failed else 0


if __name__ == "__main__":
    sys.exit(main())
