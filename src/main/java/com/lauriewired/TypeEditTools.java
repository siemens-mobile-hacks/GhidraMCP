package com.lauriewired;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;

/** Editing existing structures, unions and enums; deleting data types. */
final class TypeEditTools {

    private final McpEnvironment env;

    TypeEditTools(McpEnvironment env) {
        this.env = env;
    }

    void register(McpServer mcp) {
        mcp.tool("add_struct_field",
                "Add a field to a structure or union. Without offset the field is appended. With "
                    + "offset (structures) it replaces undefined bytes there, or is inserted (shifting "
                    + "later fields) when insert=true. bit_size creates a bit field.")
            .string("struct", "Structure/union name or path")
            .string("field_name", "Field name")
            .string("field_type", "Field data type, e.g. \"int\", \"char[16]\", \"Node *\"")
            .optInteger("offset", null, "Byte offset (structures)")
            .optBoolean("insert", false, "Insert at offset, shifting following fields")
            .optInteger("bit_size", null, "Create a bit field of this many bits")
            .optInteger("bit_offset", 0, "Bit offset within the byte at offset (bit fields)")
            .optString("comment", "", "Field comment")
            .program()
            .handler(this::addField);

        mcp.tool("update_struct_field",
                "Rename, retype and/or re-comment a structure or union field, chosen by field_name or "
                    + "field_offset.")
            .string("struct", "Structure/union name or path")
            .optString("field_name", "", "Current field name")
            .optInteger("field_offset", null, "Field offset (structures)")
            .optString("new_name", "", "New name")
            .optString("new_type", "", "New data type")
            .optString("new_comment", null, "New comment (\"\" clears)")
            .program()
            .handler(this::updateField);

        mcp.tool("delete_struct_field",
                "Delete a structure or union field by name or offset. For structures keep_layout=true "
                    + "(default) turns it into undefined bytes so later offsets stay the same; false removes "
                    + "it and shifts the following fields.")
            .string("struct", "Structure/union name or path")
            .optString("field_name", "", "Field name")
            .optInteger("field_offset", null, "Field offset (structures)")
            .optBoolean("keep_layout", true, "Keep offsets of the following fields")
            .program()
            .handler(this::deleteField);

        mcp.tool("update_enum",
                "Modify an enum: add values [{\"name\",\"value\",\"comment\"}], remove names, rename "
                    + "[{\"old\",\"new\"}], change size (1, 2, 4 or 8 bytes).")
            .string("name", "Enum name or path")
            .optArray("add", McpServer.objectSchema("name", "string", "value", "integer", "comment", "string"),
                "Values to add")
            .optArray("remove", McpServer.schema("string", null), "Names to remove")
            .optArray("rename", McpServer.objectSchema("old", "string", "new", "string"), "Names to rename")
            .optInteger("size", null, "New size in bytes")
            .program()
            .handler(this::updateEnum);

        mcp.tool("delete_data_type",
                "Delete a data type from the program. Refuses when it is used (defined data, function "
                    + "signatures/variables, other types) and lists the uses; force=true deletes anyway "
                    + "(Ghidra replaces the uses with undefined).")
            .string("name", "Data type name or path")
            .optBoolean("force", false, "Delete even if used")
            .program()
            .handler(this::deleteType);
    }

    // ------------------------------------------------------------------

    private static DataType programType(Program p, String name) {
        DataType dt = McpSupport.dataType(p, name);
        if (dt.getDataTypeManager() != p.getDataTypeManager()) {
            throw McpSupport.fail(name + " is a built-in type, not a type defined in the program");
        }
        return dt;
    }

    private static Composite composite(Program p, String name) {
        DataType dt = programType(p, name);
        if (!(dt instanceof Composite)) throw McpSupport.fail(dt.getPathName() + " is not a structure or union");
        return (Composite) dt;
    }

    private static DataTypeComponent component(Composite c, String fieldName, Integer offset) {
        if (fieldName != null && !fieldName.isBlank()) {
            for (DataTypeComponent comp : c.getDefinedComponents()) {
                if (fieldName.equals(comp.getFieldName())) return comp;
            }
            throw McpSupport.fail("No field " + fieldName + " in " + c.getName());
        }
        if (offset == null) throw McpSupport.fail("Pass field_name or field_offset");
        if (!(c instanceof Structure)) throw McpSupport.fail("field_offset is only valid for structures");
        DataTypeComponent comp = ((Structure) c).getComponentContaining(offset);
        if (comp == null || comp.getDataType() == DataType.DEFAULT && comp.getFieldName() == null) {
            throw McpSupport.fail("No defined field at offset " + offset + " in " + c.getName());
        }
        return comp;
    }

    static String layout(Composite c) {
        StringBuilder sb = new StringBuilder();
        sb.append(c instanceof Union ? "union " : "struct ").append(c.getPathName())
            .append(" (size ").append(c.getLength()).append(")\n");
        for (DataTypeComponent comp : c.getDefinedComponents()) {
            sb.append(String.format("  +0x%x %s %s", comp.getOffset(), comp.getDataType().getDisplayName(),
                comp.getFieldName() == null ? "(unnamed)" : comp.getFieldName()));
            if (comp.isBitFieldComponent()) sb.append(" (bit field)");
            if (comp.getComment() != null) sb.append(" // ").append(comp.getComment());
            sb.append('\n');
        }
        return sb.toString().trim();
    }

    private String addField(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Composite c = composite(p, a.str("struct"));
        DataType dt = McpSupport.dataType(p, a.str("field_type"));
        String name = a.str("field_name");
        String comment = a.str("comment").isEmpty() ? null : a.str("comment");
        Integer offset = a.optInteger("offset");
        Integer bits = a.optInteger("bit_size");
        McpSupport.write(p, "Add field", () -> {
            if (bits != null) {
                if (c instanceof Structure && offset != null) {
                    ((Structure) c).insertBitFieldAt(offset, dt.getLength(), a.integer("bit_offset"), dt, bits,
                        name, comment);
                }
                else {
                    c.addBitField(dt, bits, name, comment);
                }
                return null;
            }
            int len = dt.getLength() > 0 ? dt.getLength() : 1;
            if (offset == null) {
                c.add(dt, len, name, comment);
            }
            else {
                if (!(c instanceof Structure)) throw McpSupport.fail("offset is only valid for structures");
                Structure s = (Structure) c;
                if (a.bool("insert")) {
                    s.insertAtOffset(offset, dt, len, name, comment);
                }
                else {
                    for (int i = 0; i < len; i++) {
                        DataTypeComponent existing = s.getComponentContaining(offset + i);
                        if (existing != null && existing.getDataType() != DataType.DEFAULT) {
                            throw McpSupport.fail("Offset " + (offset + i) + " is occupied by "
                                + existing.getFieldName() + "; use insert=true or update_struct_field");
                        }
                    }
                    s.replaceAtOffset(offset, dt, len, name, comment);
                }
            }
            return null;
        });
        return "Added " + name + "\n" + layout(c);
    }

    private String updateField(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Composite c = composite(p, a.str("struct"));
        DataTypeComponent comp = component(c, a.str("field_name"), a.optInteger("field_offset"));
        String newName = a.str("new_name");
        String newType = a.str("new_type");
        String newComment = a.str("new_comment");
        if (newName.isEmpty() && newType.isEmpty() && newComment == null) {
            throw McpSupport.fail("Pass new_name, new_type and/or new_comment");
        }
        DataType dt = newType.isEmpty() ? null : McpSupport.dataType(p, newType);
        int ordinal = comp.getOrdinal();
        McpSupport.write(p, "Update field", () -> {
            DataTypeComponent target = c.getComponent(ordinal);
            String name = newName.isEmpty() ? target.getFieldName() : newName;
            String comment = newComment == null ? target.getComment() : (newComment.isEmpty() ? null : newComment);
            if (dt != null) {
                int len = dt.getLength() > 0 ? dt.getLength() : target.getLength();
                if (c instanceof Structure) {
                    ((Structure) c).replace(ordinal, dt, len, name, comment);
                }
                else {
                    c.delete(ordinal);
                    c.insert(ordinal, dt, len, name, comment);
                }
            }
            else {
                if (!newName.isEmpty()) target.setFieldName(name);
                if (newComment != null) target.setComment(comment);
            }
            return null;
        });
        return "Updated field\n" + layout(c);
    }

    private String deleteField(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Composite c = composite(p, a.str("struct"));
        DataTypeComponent comp = component(c, a.str("field_name"), a.optInteger("field_offset"));
        String name = comp.getFieldName();
        int ordinal = comp.getOrdinal();
        boolean keep = a.bool("keep_layout");
        McpSupport.write(p, "Delete field", () -> {
            if (c instanceof Structure && keep) ((Structure) c).clearComponent(ordinal);
            else c.delete(ordinal);
            return null;
        });
        return "Deleted field " + name + "\n" + layout(c);
    }

    private String updateEnum(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        DataType dt = programType(p, a.str("name"));
        if (!(dt instanceof Enum)) throw McpSupport.fail(dt.getPathName() + " is not an enum");
        Enum existing = (Enum) dt;
        JsonArray add = a.array("add");
        JsonArray remove = a.array("remove");
        JsonArray rename = a.array("rename");
        Integer size = a.optInteger("size");
        if (add.size() == 0 && remove.size() == 0 && rename.size() == 0 && size == null) {
            throw McpSupport.fail("Nothing to change: pass add, remove, rename or size");
        }
        McpSupport.write(p, "Update enum", () -> {
            EnumDataType copy = (EnumDataType) existing.copy(p.getDataTypeManager());
            if (size != null) {
                if (size != 1 && size != 2 && size != 4 && size != 8) throw McpSupport.fail("size must be 1, 2, 4 or 8");
                copy.setLength(size);
            }
            for (JsonElement e : remove) {
                String n = e.getAsString();
                if (!copy.contains(n)) throw McpSupport.fail("Enum has no value " + n);
                copy.remove(n);
            }
            for (JsonElement e : rename) {
                JsonObject o = e.getAsJsonObject();
                String old = o.get("old").getAsString();
                if (!copy.contains(old)) throw McpSupport.fail("Enum has no value " + old);
                long v = copy.getValue(old);
                String c = copy.getComment(old);
                copy.remove(old);
                copy.add(o.get("new").getAsString(), v, c);
            }
            for (JsonElement e : add) {
                JsonObject o = e.getAsJsonObject();
                String n = o.get("name").getAsString();
                if (copy.contains(n)) throw McpSupport.fail("Enum already has " + n);
                copy.add(n, o.get("value").getAsLong(), o.has("comment") ? o.get("comment").getAsString() : null);
            }
            existing.replaceWith(copy);
            return null;
        });
        StringBuilder sb = new StringBuilder("enum " + existing.getPathName() + " (size " + existing.getLength() + ")");
        for (String n : existing.getNames()) {
            sb.append("\n  ").append(n).append(" = ").append(McpSupport.hex(existing.getValue(n)));
        }
        return sb.toString();
    }

    private String deleteType(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        DataType dt = programType(p, a.str("name"));
        String path = dt.getPathName();
        List<String> uses = McpSupport.onSwing(() -> usages(p, dt, 20));
        if (!uses.isEmpty() && !a.bool("force")) {
            throw McpSupport.fail(path + " is in use:\n  " + String.join("\n  ", uses)
                + "\nPass force=true to delete it anyway.");
        }
        DataTypeManager dtm = p.getDataTypeManager();
        McpSupport.write(p, "Delete data type", () -> {
            if (!dtm.remove(dt)) throw McpSupport.fail("Ghidra refused to delete " + path);
            return null;
        });
        return "Deleted " + path + (uses.isEmpty() ? "" : " (it had " + uses.size() + "+ uses)");
    }

    private static boolean uses(DataType candidate, DataType dt) {
        return candidate != null && (candidate.equals(dt) || candidate.isEquivalent(dt) && candidate.getName().equals(dt.getName())
            || candidate.dependsOn(dt));
    }

    static List<String> usages(Program p, DataType dt, int max) {
        List<String> out = new ArrayList<>();
        for (DataType other : p.getDataTypeManager().getDataTypesContaining(dt)) {
            if (out.size() >= max) return out;
            if (other != dt) out.add("type " + other.getPathName());
        }
        DataIterator it = p.getListing().getDefinedData(true);
        while (it.hasNext() && out.size() < max) {
            Data d = it.next();
            if (uses(d.getDataType(), dt)) out.add("data at " + d.getAddress());
        }
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            if (out.size() >= max) break;
            if (uses(f.getReturnType(), dt)) {
                out.add("return type of " + McpSupport.fqn(f));
                continue;
            }
            for (Variable v : f.getAllVariables()) {
                if (uses(v.getDataType(), dt)) {
                    out.add("variable " + v.getName() + " in " + McpSupport.fqn(f));
                    break;
                }
            }
        }
        return out;
    }
}
