package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.CategoryPath;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.util.cparser.C.CParser;

import javax.swing.SwingUtilities;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Data type listing, description and creation (struct, union, enum, typedef, C parsing). Part of the original GhidraMCP tool set. */
final class TypeTools extends CoreTool {

    TypeTools(McpEnvironment env, DecompilerService decompiler) {
        super(env, decompiler);
    }

    @Override
    void registerMcp(McpServer mcp) {
        mcp.tool("list_data_types", "List program data types, optionally filtered by name/path and category.")
            .optString("query", "", "Optional name/path filter")
            .optString("category", "", "Optional category filter")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of results")
            .program()
            .handler(a -> listDataTypes(a.str("program"), a.str("query"), a.str("category"),
                a.integer("offset"), a.integer("limit")));

        mcp.tool("get_data_type", "Describe a data type, including struct/union fields or enum values.")
            .string("name", "Data type name or path")
            .program()
            .handler(a -> getDataTypeDescription(a.str("program"), a.str("name")));

        mcp.tool("create_enum", "Create an enum data type. Each value: {\"name\": \"MEMBER_NAME\", \"value\": 0}")
            .string("name", "Enum name")
            .array("values", McpServer.objectSchema("name", "string", "value", "integer"), "Enum members")
            .optInteger("size", 4, "Enum size in bytes")
            .optString("category", "/", "Category path")
            .optString("description", "", "Optional description")
            .program()
            .handler(a -> createEnum(a.str("program"),
                a.object("name", "size", "category", "description", "values").toString()));

        JsonObject fieldSchema = McpServer.objectSchema("name", "string", "type", "string", "size", "integer",
            "offset", "integer", "comment", "string", "bit_size", "integer");

        mcp.tool("create_struct",
                "Create a structure data type. Each field accepts name, type, and optional size, offset, "
                    + "comment, or bit_size. Type strings may include pointers and arrays, "
                    + "e.g. \"Node *\" or \"char[32]\".")
            .string("name", "Structure name")
            .array("fields", fieldSchema, "Structure fields")
            .optString("category", "/", "Category path")
            .optInteger("size", 0, "Explicit structure size; 0 to grow with fields")
            .optBoolean("packed", false, "Enable packing")
            .optInteger("packing", 0, "Explicit packing value")
            .optInteger("alignment", 0, "Explicit minimum alignment")
            .optString("description", "", "Optional description")
            .program()
            .handler(a -> createStruct(a.str("program"), a.object("name", "category", "size", "packed",
                "packing", "alignment", "description", "fields").toString()));

        mcp.tool("create_union", "Create or replace a union data type using the same field format as create_struct.")
            .string("name", "Union name")
            .array("fields", fieldSchema, "Union fields")
            .optString("category", "/", "Category path")
            .optBoolean("packed", false, "Enable packing")
            .optInteger("packing", 0, "Explicit packing value")
            .optInteger("alignment", 0, "Explicit minimum alignment")
            .optString("description", "", "Optional description")
            .program()
            .handler(a -> createUnion(a.str("program"), a.object("name", "category", "packed",
                "packing", "alignment", "description", "fields").toString()));

        mcp.tool("create_typedef", "Create or replace a typedef. The base type may be a pointer or array expression.")
            .string("name", "Typedef name")
            .string("base_type", "Base type expression")
            .optString("category", "/", "Category path")
            .program()
            .handler(a -> createTypedef(a.str("program"), a.object("name", "base_type", "category").toString()));

        mcp.tool("parse_c_types",
                "Parse C declarations with Ghidra's native CParser and add the resulting structs, unions, "
                    + "enums, typedefs, and function definitions to the program.")
            .string("code", "C declarations")
            .optString("category", "/", "Category path")
            .program()
            .handler(a -> parseCTypes(a.str("program"), a.object("code", "category").toString()));
    }

    String listDataTypes(String programName, String query, String category,
                                 int offset, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";

        String queryLower = query == null ? "" : query.toLowerCase(Locale.ROOT);
        String categoryPrefix = category == null ? "" : category.trim();
        List<String> lines = new ArrayList<>();
        Iterator<DataType> iterator = program.getDataTypeManager().getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dt = iterator.next();
            String path = dt.getPathName();
            if (!queryLower.isEmpty() && !path.toLowerCase(Locale.ROOT).contains(queryLower)) continue;
            if (!categoryPrefix.isEmpty() && !path.startsWith(categoryPrefix)) continue;
            lines.add(path + "\t" + dataTypeKind(dt) + "\t" + dt.getLength());
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    String getDataTypeDescription(String programName, String name) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (name == null || name.trim().isEmpty()) return "Data type name is required";

        DataType dt = resolveDataType(program.getDataTypeManager(), name);
        if (dt == null) return "Data type not found: " + name;

        StringBuilder result = new StringBuilder();
        result.append("Path: ").append(dt.getPathName()).append('\n');
        result.append("Kind: ").append(dataTypeKind(dt)).append('\n');
        result.append("Size: ").append(dt.getLength()).append(" bytes\n");

        if (dt instanceof Composite) {
            Composite composite = (Composite) dt;
            result.append("Alignment: ").append(composite.getAlignment()).append('\n');
            result.append("Packing: ").append(composite.getPackingType()).append('\n');
            result.append("Fields:\n");
            for (DataTypeComponent component : composite.getDefinedComponents()) {
                result.append("  +").append(component.getOffset()).append("  ")
                    .append(component.getDataType().getDisplayName()).append("  ")
                    .append(component.getFieldName() == null ? component.getDefaultFieldName()
                                                            : component.getFieldName())
                    .append("  [").append(component.getLength()).append(" bytes]");
                if (component.getComment() != null && !component.getComment().isEmpty()) {
                    result.append("  // ").append(component.getComment());
                }
                result.append('\n');
            }
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
            result.append("Values:\n");
            String[] names = enumType.getNames();
            Arrays.sort(names);
            for (String entryName : names) {
                result.append("  ").append(entryName).append(" = ")
                    .append(enumType.getValue(entryName)).append('\n');
            }
        } else if (dt instanceof TypeDef) {
            result.append("Base type: ").append(((TypeDef) dt).getBaseDataType().getPathName())
                .append('\n');
        }
        return result.toString();
    }

    String dataTypeKind(DataType dt) {
        if (dt instanceof ghidra.program.model.data.Structure) return "struct";
        if (dt instanceof ghidra.program.model.data.Union) return "union";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof ghidra.program.model.data.Pointer) return "pointer";
        if (dt instanceof ghidra.program.model.data.Array) return "array";
        if (dt instanceof ghidra.program.model.data.FunctionDefinition) return "function";
        return dt.getClass().getSimpleName();
    }

    String createEnum(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create enum");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            int size = body.has("size") ? body.get("size").getAsInt() : 4;
            JsonArray values = body.getAsJsonArray("values");
            if (size != 1 && size != 2 && size != 4 && size != 8) {
                return "Enum size must be 1, 2, 4, or 8 bytes";
            }
            if (values == null || values.isEmpty()) return "Enum values are required";
            CategoryPath category = getCategoryPath(body);
            String description = getOptionalJsonString(body, "description");

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    EnumDataType enumType = new EnumDataType(category, name, size, dtm);
                    if (description != null) enumType.setDescription(description);

                    for (JsonElement el : values) {
                        JsonObject entry = el.getAsJsonObject();
                        String entryName = entry.get("name").getAsString();
                        long entryValue = entry.get("value").getAsLong();
                        enumType.add(entryName, entryValue);
                    }

                    DataType stored = dtm.addDataType(enumType, DataTypeConflictHandler.REPLACE_HANDLER);
                    success = true;
                    result.set("Enum '" + stored.getPathName() + "' created with " +
                        values.size() + " values (" + stored.getLength() + " bytes)");
                } catch (Exception e) {
                    Msg.error(this, "Error creating enum", e);
                    result.set("Error creating enum: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    String createStruct(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create struct");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            JsonArray fields = body.getAsJsonArray("fields");
            if (fields == null) return "Struct fields are required";
            CategoryPath category = getCategoryPath(body);
            int requestedSize = body.has("size") ? body.get("size").getAsInt() : 0;
            if (requestedSize < 0) return "Struct size cannot be negative";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create struct");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    StructureDataType candidate = new StructureDataType(category, name, 0, dtm);
                    DataType stored = dtm.addDataType(candidate, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (!(stored instanceof ghidra.program.model.data.Structure)) {
                        throw new IllegalArgumentException("A non-struct type already uses " + stored.getPathName());
                    }
                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) stored;
                    while (struct.getNumComponents() > 0) struct.delete(0);
                    configureComposite(struct, body);
                    addCompositeFields(struct, fields, dtm, true);
                    if (requestedSize > 0) {
                        if (struct.getLength() > requestedSize) {
                            throw new IllegalArgumentException("Fields require " + struct.getLength() +
                                " bytes, exceeding requested struct size " + requestedSize);
                        }
                        struct.setLength(requestedSize);
                    }
                    success = true;
                    result.set("Struct '" + struct.getPathName() + "' created with " + fields.size() +
                        " fields, total size: " + struct.getLength() + " bytes");
                } catch (Exception e) {
                    Msg.error(this, "Error creating struct", e);
                    result.set("Error creating struct: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    String createUnion(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create union");
        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            JsonArray fields = body.getAsJsonArray("fields");
            if (fields == null || fields.isEmpty()) return "Union fields are required";
            CategoryPath category = getCategoryPath(body);

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create union");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    UnionDataType candidate = new UnionDataType(category, name, dtm);
                    DataType stored = dtm.addDataType(candidate, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (!(stored instanceof ghidra.program.model.data.Union)) {
                        throw new IllegalArgumentException("A non-union type already uses " + stored.getPathName());
                    }
                    ghidra.program.model.data.Union union = (ghidra.program.model.data.Union) stored;
                    while (union.getNumComponents() > 0) union.delete(0);
                    configureComposite(union, body);
                    addCompositeFields(union, fields, dtm, false);
                    success = true;
                    result.set("Union '" + union.getPathName() + "' created with " + fields.size() +
                        " fields, total size: " + union.getLength() + " bytes");
                } catch (Exception e) {
                    Msg.error(this, "Error creating union", e);
                    result.set("Error creating union: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }
        return result.get();
    }

    String createTypedef(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create typedef");
        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String name = getRequiredJsonString(body, "name");
            String baseTypeName = getRequiredJsonString(body, "base_type");
            CategoryPath category = getCategoryPath(body);

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create typedef");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseType = resolveDataType(dtm, baseTypeName);
                    if (baseType == null) {
                        throw new IllegalArgumentException("Unknown base data type: " + baseTypeName);
                    }
                    TypedefDataType typedef = new TypedefDataType(category, name, baseType, dtm);
                    DataType stored = dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);
                    success = true;
                    result.set("Typedef '" + stored.getPathName() + "' created for " +
                        baseType.getDisplayName() + " (" + stored.getLength() + " bytes)");
                } catch (Exception e) {
                    Msg.error(this, "Error creating typedef", e);
                    result.set("Error creating typedef: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }
        return result.get();
    }

    String parseCTypes(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to parse C types");
        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String code = getRequiredJsonString(body, "code");
            CategoryPath category = getCategoryPath(body);
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Parse C data types");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Set<Long> existingIds = new HashSet<>();
                    Iterator<DataType> beforeIterator = dtm.getAllDataTypes();
                    while (beforeIterator.hasNext()) existingIds.add(dtm.getID(beforeIterator.next()));
                    int before = dtm.getDataTypeCount(false);
                    CParser parser = new CParser(dtm, true, new DataTypeManager[0]);
                    DataType last = parser.parse(code);
                    int added = Math.max(0, dtm.getDataTypeCount(false) - before);
                    if (!category.isRoot()) {
                        dtm.createCategory(category);
                        Iterator<DataType> afterIterator = dtm.getAllDataTypes();
                        while (afterIterator.hasNext()) {
                            DataType parsedType = afterIterator.next();
                            if (!existingIds.contains(dtm.getID(parsedType)) &&
                                    (parsedType instanceof Composite ||
                                     parsedType instanceof ghidra.program.model.data.Enum ||
                                     parsedType instanceof TypeDef ||
                                     parsedType instanceof ghidra.program.model.data.FunctionDefinition)) {
                                parsedType.setCategoryPath(category);
                            }
                        }
                    }
                    String messages = parser.getParseMessages();
                    success = true;
                    result.set("C declarations parsed; data types added: " + added +
                        "; category: " + category.getPath() +
                        (last == null ? "" : "; last type: " + last.getPathName()) +
                        (messages == null || messages.isBlank() ? "" : "\nParser messages:\n" + messages));
                } catch (Exception e) {
                    Msg.error(this, "Error parsing C types", e);
                    result.set("Error parsing C types: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }
        return result.get();
    }

    void configureComposite(Composite composite, JsonObject body) {
        String description = getOptionalJsonString(body, "description");
        if (description != null) composite.setDescription(description);
        boolean packed = body.has("packed") && body.get("packed").getAsBoolean();
        int packing = body.has("packing") ? body.get("packing").getAsInt() : 0;
        int alignment = body.has("alignment") ? body.get("alignment").getAsInt() : 0;
        if (packing < 0 || alignment < 0) {
            throw new IllegalArgumentException("Packing and alignment cannot be negative");
        }
        if (packing > 0) composite.setExplicitPackingValue(packing);
        else composite.setPackingEnabled(packed);
        if (alignment > 0) composite.setExplicitMinimumAlignment(alignment);
    }

    void addCompositeFields(Composite composite, JsonArray fields, DataTypeManager dtm,
                                    boolean allowOffsets) throws Exception {
        for (JsonElement element : fields) {
            JsonObject field = element.getAsJsonObject();
            String fieldName = getRequiredJsonString(field, "name");
            String fieldType = getRequiredJsonString(field, "type");
            String comment = getOptionalJsonString(field, "comment");
            DataType dt = resolveDataType(dtm, fieldType);
            if (dt == null) throw new IllegalArgumentException("Unknown field type: " + fieldType);

            if (field.has("bit_size")) {
                if (field.has("offset")) {
                    throw new IllegalArgumentException("Explicit offsets for bit-fields are not supported; use C declarations");
                }
                composite.addBitField(dt, field.get("bit_size").getAsInt(), fieldName, comment);
                continue;
            }

            int fieldSize = field.has("size") ? field.get("size").getAsInt() : dt.getLength();
            if (fieldSize <= 0) {
                throw new IllegalArgumentException("Field '" + fieldName +
                    "' requires an explicit positive size");
            }
            if (field.has("offset")) {
                if (!allowOffsets || !(composite instanceof ghidra.program.model.data.Structure)) {
                    throw new IllegalArgumentException("Explicit offsets are only valid for structs");
                }
                int offset = field.get("offset").getAsInt();
                if (offset < 0) throw new IllegalArgumentException("Field offset cannot be negative");
                ((ghidra.program.model.data.Structure) composite).insertAtOffset(
                    offset, dt, fieldSize, fieldName, comment);
            } else {
                composite.add(dt, fieldSize, fieldName, comment);
            }
        }
    }

    CategoryPath getCategoryPath(JsonObject body) {
        String category = getOptionalJsonString(body, "category");
        if (category == null || category.isBlank() || category.equals("/")) return CategoryPath.ROOT;
        if (!category.startsWith("/")) category = "/" + category;
        return new CategoryPath(category);
    }

    String getRequiredJsonString(JsonObject body, String key) {
        String value = getOptionalJsonString(body, key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("JSON field '" + key + "' is required");
        }
        return value.trim();
    }

    String getOptionalJsonString(JsonObject body, String key) {
        return body.has(key) && !body.get(key).isJsonNull() ? body.get(key).getAsString() : null;
    }
}
