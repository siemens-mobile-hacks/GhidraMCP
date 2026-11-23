package com.lauriewired;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.CodeUnitInsertionException;

/** Symbols, data listing/updates, strings and comments. */
final class SymbolTools {

    private static final String COMMENT_TYPES = "pre, post, eol, plate, repeatable";

    private final McpEnvironment env;

    SymbolTools(McpEnvironment env) {
        this.env = env;
    }

    void register(McpServer mcp) {
        mcp.tool("list_symbols",
                "List symbols as \"qualified_name @ address [type, source, primary]\". Filters: "
                    + "type (function, label, external, namespace, class, library, parameter, local, global_var), "
                    + "source (user, imported, analysis, default), name_contains, name_regex, address.")
            .optString("type", "", "Symbol type filter")
            .optString("source", "", "Source filter")
            .optString("name_contains", "", "Case-insensitive substring of the qualified name")
            .optString("name_regex", "", "Regular expression matched against the qualified name")
            .optString("address", "", "Only symbols at this address")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 200, "Maximum number of results")
            .program()
            .handler(this::listSymbols);

        mcp.tool("rename_symbol",
                "Rename a symbol (label, function or data label) at an address. When several symbols "
                    + "share the address, pass old_name. new_name may be qualified (A::B::x, ::x).")
            .string("address", "Symbol address")
            .optString("old_name", "", "Current name when the address has several symbols")
            .string("new_name", "New name")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                Symbol s = symbolAt(p, a.str("address"), a.str("old_name"));
                String old = McpSupport.fqn(s);
                McpSupport.write(p, "Rename symbol", () -> {
                    McpSupport.applyName(p, s, a.str("new_name"));
                    return null;
                });
                return "Renamed " + old + " -> " + McpSupport.fqn(s) + " at " + s.getAddress();
            });

        mcp.tool("delete_symbol",
                "Delete a label at an address (pass name when several labels share it). Function "
                    + "symbols are refused — use delete_function.")
            .string("address", "Symbol address")
            .optString("name", "", "Symbol name when the address has several")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                Symbol s = symbolAt(p, a.str("address"), a.str("name"));
                if (s.getSymbolType() == SymbolType.FUNCTION) {
                    throw McpSupport.fail(McpSupport.fqn(s) + " is a function; use delete_function");
                }
                String name = McpSupport.fqn(s);
                McpSupport.write(p, "Delete symbol", () -> {
                    if (!s.delete()) throw McpSupport.fail("Ghidra refused to delete " + name);
                    return null;
                });
                return "Deleted symbol " + name + " at " + a.str("address");
            });

        mcp.tool("set_primary_symbol",
                "Make one of several symbols at an address the primary (displayed) one.")
            .string("address", "Symbol address")
            .string("name", "Name of the symbol to make primary")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                Symbol s = symbolAt(p, a.str("address"), a.str("name"));
                McpSupport.write(p, "Set primary symbol", () -> {
                    if (!s.setPrimary()) throw McpSupport.fail("Ghidra refused to make " + s.getName() + " primary");
                    return null;
                });
                return McpSupport.fqn(s) + " is now the primary symbol at " + s.getAddress();
            });

        mcp.tool("list_data_items",
                "List defined data as \"address: label = value [type]\". Filters: name_contains "
                    + "(label, case-insensitive), type (data type name substring, e.g. dword, string, "
                    + "MyStruct), start_address/end_address.")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of results")
            .optString("name_contains", "", "Label substring")
            .optString("type", "", "Data type name substring")
            .optString("start_address", "", "Lowest address")
            .optString("end_address", "", "Highest address")
            .program()
            .handler(this::listData);

        mcp.tool("update_data",
                "Change a data item atomically: any of data_type (re-defines the item, clearing "
                    + "conflicting data but never instructions), label (qualified names allowed) and "
                    + "comment (EOL comment; empty string clears).")
            .string("address", "Data address")
            .optString("data_type", "", "New data type")
            .optString("label", "", "New label")
            .optString("comment", null, "New EOL comment (\"\" clears)")
            .program()
            .handler(this::updateData);

        mcp.tool("list_strings",
                "List defined strings as \"address: \\\"value\\\" (length, type[, label])\". The filter "
                    + "is a case-insensitive substring of the string value.")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 200, "Maximum number of strings")
            .optString("filter", "", "Substring of the string value")
            .program()
            .handler(this::listStrings);

        mcp.tool("get_comments",
                "All comments (plate, pre, post, eol, repeatable) at an address, or in a range when "
                    + "end_address is given.")
            .string("address", "Start address")
            .optString("end_address", "", "End address (inclusive) for a range")
            .optInteger("limit", 500, "Maximum number of commented addresses in a range")
            .program()
            .handler(this::getComments);

        mcp.tool("set_comment",
                "Set a comment of any type at an address: comment_type is one of " + COMMENT_TYPES
                    + " (pre = shown in the decompiler, eol = end of line in the listing). Empty clears it.")
            .string("address", "Address")
            .string("comment", "Comment text (\"\" clears)")
            .optString("comment_type", "eol", COMMENT_TYPES)
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                Address addr = McpSupport.address(p, a.str("address"));
                CommentType type = commentType(a.str("comment_type"));
                String c = a.str("comment");
                McpSupport.write(p, "Set comment", () -> {
                    p.getListing().setComment(addr, type, c.isEmpty() ? null : c);
                    return null;
                });
                return (c.isEmpty() ? "Cleared " : "Set ") + type.name().toLowerCase(Locale.ROOT)
                    + " comment at " + addr;
            });
    }

    // ------------------------------------------------------------------

    static CommentType commentType(String text) {
        String t = text == null || text.isBlank() ? "eol" : text.trim().toLowerCase(Locale.ROOT);
        switch (t) {
            case "pre":
            case "decompiler":
                return CommentType.PRE;
            case "post":
                return CommentType.POST;
            case "eol":
            case "disassembly":
                return CommentType.EOL;
            case "plate":
                return CommentType.PLATE;
            case "repeatable":
                return CommentType.REPEATABLE;
            default:
                throw McpSupport.fail("Unknown comment_type '" + text + "'; use " + COMMENT_TYPES);
        }
    }

    private static Symbol symbolAt(Program p, String address, String name) {
        Address a = McpSupport.address(p, address);
        Symbol[] symbols = p.getSymbolTable().getSymbols(a);
        if (symbols.length == 0) throw McpSupport.fail("No symbol at " + a);
        if (name == null || name.isBlank()) {
            if (symbols.length > 1) {
                List<String> names = new ArrayList<>();
                for (Symbol s : symbols) names.add(McpSupport.fqn(s));
                throw McpSupport.fail("Several symbols at " + a + ": " + String.join(", ", names)
                    + "; pass the name");
            }
            return symbols[0];
        }
        for (Symbol s : symbols) {
            if (s.getName().equals(name) || McpSupport.fqn(s).equals(name)) return s;
        }
        throw McpSupport.fail("No symbol named " + name + " at " + a);
    }

    private static String typeName(Symbol s) {
        SymbolType t = s.getSymbolType();
        if (t == SymbolType.LABEL) {
            if (s.isExternal()) return "external";
            Data d = s.getProgram().getListing().getDataAt(s.getAddress());
            return d != null && d.isDefined() ? "global_var" : "label";
        }
        if (t == SymbolType.FUNCTION) return s.isExternal() ? "external function" : "function";
        return t.toString().toLowerCase(Locale.ROOT);
    }

    private static boolean typeMatches(Symbol s, String filter) {
        if (filter.isEmpty()) return true;
        String t = typeName(s);
        switch (filter) {
            case "function":
                return s.getSymbolType() == SymbolType.FUNCTION && !s.isExternal();
            case "external":
                return s.isExternal();
            case "label":
                return t.equals("label") || t.equals("global_var");
            default:
                return t.equals(filter);
        }
    }

    private static boolean sourceMatches(Symbol s, String filter) {
        if (filter.isEmpty()) return true;
        SourceType src = s.getSource();
        switch (filter) {
            case "user":
            case "user_defined":
                return src == SourceType.USER_DEFINED;
            case "imported":
                return src == SourceType.IMPORTED;
            case "analysis":
                return src == SourceType.ANALYSIS;
            case "default":
                return src == SourceType.DEFAULT;
            default:
                throw McpSupport.fail("Unknown source '" + filter + "'; use user, imported, analysis, default");
        }
    }

    private static void sourceMatchesName(String filter) {
        switch (filter) {
            case "user":
            case "user_defined":
            case "imported":
            case "analysis":
            case "default":
                return;
            default:
                throw McpSupport.fail("Unknown source '" + filter + "'; use user, imported, analysis, default");
        }
    }

    private String listSymbols(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        String type = a.str("type").trim().toLowerCase(Locale.ROOT);
        String source = a.str("source").trim().toLowerCase(Locale.ROOT);
        String contains = a.str("name_contains").toLowerCase(Locale.ROOT);
        Pattern regex = McpSupport.regex(a.str("name_regex"));
        Address at = a.str("address").isEmpty() ? null : McpSupport.address(p, a.str("address"));
        if (!source.isEmpty()) sourceMatchesName(source);
        return McpSupport.onSwing(() -> {
            SymbolTable st = p.getSymbolTable();
            List<String> lines = new ArrayList<>();
            Iterable<Symbol> symbols = at != null ? List.of(st.getSymbols(at)) : st.getAllSymbols(true);
            for (Symbol s : symbols) {
                if (!typeMatches(s, type) || !sourceMatches(s, source)) continue;
                String q = McpSupport.fqn(s);
                if (!contains.isEmpty() && !q.toLowerCase(Locale.ROOT).contains(contains)) continue;
                if (regex != null && !regex.matcher(q).find()) continue;
                lines.add(q + " @ " + s.getAddress() + " [" + typeName(s) + ", "
                    + s.getSource().toString().toLowerCase(Locale.ROOT)
                    + (s.isPrimary() ? ", primary" : "") + "]");
            }
            return McpSupport.page(lines, a.integer("offset"), a.integer("limit"));
        });
    }

    private String listData(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        String contains = a.str("name_contains").toLowerCase(Locale.ROOT);
        String type = a.str("type").toLowerCase(Locale.ROOT);
        Address start = a.str("start_address").isEmpty() ? null : McpSupport.address(p, a.str("start_address"));
        Address end = a.str("end_address").isEmpty() ? null : McpSupport.address(p, a.str("end_address"));
        return McpSupport.onSwing(() -> {
            List<String> lines = new ArrayList<>();
            Listing listing = p.getListing();
            DataIterator it = start == null ? listing.getDefinedData(true) : listing.getDefinedData(start, true);
            while (it.hasNext()) {
                Data d = it.next();
                if (end != null && d.getAddress().compareTo(end) > 0) break;
                String label = d.getLabel() == null ? "(unnamed)" : d.getLabel();
                if (!contains.isEmpty() && !label.toLowerCase(Locale.ROOT).contains(contains)) continue;
                String tn = d.getDataType().getDisplayName();
                if (!type.isEmpty() && !tn.toLowerCase(Locale.ROOT).contains(type)) continue;
                lines.add(d.getAddress() + ": " + escape(label) + " = " + escape(d.getDefaultValueRepresentation())
                    + " [" + tn + "]");
            }
            return McpSupport.page(lines, a.integer("offset"), a.integer("limit"));
        });
    }

    private String updateData(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Address addr = McpSupport.address(p, a.str("address"));
        String typeText = a.str("data_type");
        String label = a.str("label");
        String comment = a.str("comment");
        if (typeText.isEmpty() && label.isEmpty() && comment == null) {
            throw McpSupport.fail("Pass data_type, label and/or comment");
        }
        DataType dt = typeText.isEmpty() ? null : McpSupport.dataType(p, typeText);
        List<String> done = new ArrayList<>();
        McpSupport.write(p, "Update data", () -> {
            Listing listing = p.getListing();
            if (dt != null) {
                int len = dt.getLength();
                if (len <= 0) throw McpSupport.fail(dt.getDisplayName() + " has no fixed length");
                Address last = addr.add(len - 1);
                if (listing.getInstructions(new ghidra.program.model.address.AddressSet(addr, last), true).hasNext()) {
                    throw McpSupport.fail("Instructions exist in " + addr + "-" + last + "; not overwriting code");
                }
                listing.clearCodeUnits(addr, last, false);
                try {
                    listing.createData(addr, dt);
                }
                catch (CodeUnitInsertionException e) {
                    throw McpSupport.fail("Cannot define " + dt.getDisplayName() + " at " + addr + ": " + e.getMessage());
                }
                done.add("type " + dt.getDisplayName());
            }
            if (!label.isEmpty()) {
                Symbol primary = p.getSymbolTable().getPrimarySymbol(addr);
                if (primary != null && primary.getSource() != SourceType.DEFAULT) {
                    McpSupport.applyName(p, primary, label);
                }
                else {
                    Symbol s = p.getSymbolTable().createLabel(addr, "tmp_mcp_label", SourceType.USER_DEFINED);
                    McpSupport.applyName(p, s, label);
                    s.setPrimary();
                }
                done.add("label " + label);
            }
            if (comment != null) {
                listing.setComment(addr, CommentType.EOL, comment.isEmpty() ? null : comment);
                done.add(comment.isEmpty() ? "comment cleared" : "comment");
            }
            return null;
        });
        Data d = McpSupport.onSwing(() -> p.getListing().getDataAt(addr));
        return "Updated " + addr + ": " + String.join(", ", done)
            + (d == null ? "" : "\nNow: " + d.getDataType().getDisplayName() + " " + d.getLabel()
                + " = " + d.getDefaultValueRepresentation());
    }

    private String listStrings(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        String filter = a.str("filter").toLowerCase(Locale.ROOT);
        return McpSupport.onSwing(() -> {
            List<String> lines = new ArrayList<>();
            DataIterator it = p.getListing().getDefinedData(true);
            while (it.hasNext()) {
                Data d = it.next();
                if (!StringDataInstance.isString(d)) continue;
                Object v = d.getValue();
                String value = v == null ? "" : v.toString();
                if (!filter.isEmpty() && !value.toLowerCase(Locale.ROOT).contains(filter)) continue;
                String label = d.getLabel();
                lines.add(d.getAddress() + ": \"" + escape(value) + "\" (" + value.length() + ", "
                    + d.getDataType().getName() + (label == null ? "" : ", " + label) + ")");
            }
            return McpSupport.page(lines, a.integer("offset"), a.integer("limit"));
        });
    }

    private String getComments(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Address start = McpSupport.address(p, a.str("address"));
        Address end = a.str("end_address").isEmpty() ? null : McpSupport.address(p, a.str("end_address"));
        int limit = a.integer("limit");
        return McpSupport.onSwing(() -> {
            Listing listing = p.getListing();
            if (end == null) {
                StringBuilder sb = new StringBuilder();
                for (CommentType t : CommentType.values()) {
                    String c = listing.getComment(t, start);
                    if (c != null) sb.append(t.name().toLowerCase(Locale.ROOT)).append(": ").append(c).append('\n');
                }
                return sb.length() == 0 ? "No comments at " + start : sb.toString().trim();
            }
            List<String> lines = new ArrayList<>();
            ghidra.program.model.address.AddressIterator it = listing.getCommentAddressIterator(
                new ghidra.program.model.address.AddressSet(start, end), true);
            while (it.hasNext() && lines.size() < limit) {
                Address addr = it.next();
                for (CommentType t : CommentType.values()) {
                    String c = listing.getComment(t, addr);
                    if (c != null) lines.add(addr + " " + t.name().toLowerCase(Locale.ROOT) + ": " + c);
                }
            }
            return lines.isEmpty() ? "No comments in " + start + "-" + end : String.join("\n", lines);
        });
    }

    private static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                default:
                    if (ch < 32) sb.append(String.format("\\x%02x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.toString();
    }
}
