package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Defining, clearing, reading and applying data. Part of the original GhidraMCP tool set. */
final class DataTools extends CoreTool {

    DataTools(McpEnvironment env, DecompilerService decompiler) {
        super(env, decompiler);
    }

    @Override
    void registerMcp(McpServer mcp) {
        mcp.tool("clear_data",
                "Clear (undefine) data at an address, reverting bytes to undefined state. "
                    + "If size is omitted, clears the single data item at that address.")
            .string("address", "Address in hex")
            .optInteger("size", null, "Optional number of bytes to clear")
            .program()
            .handler(a -> {
                Integer size = a.optInteger("size");
                return clearData(a.str("program"), a.str("address"), size == null ? null : size.toString());
            });

        mcp.tool("define_data_batch",
                "Create multiple data definitions in a single transaction. "
                    + "Each item: {\"address\": \"0x...\", \"data_type\": \"dword\", \"label\": \"optional_name\"}")
            .array("items", McpServer.objectSchema("address", "string", "data_type", "string",
                "label", "string"), "Data definitions")
            .program()
            .handler(a -> defineDataBatch(a.str("program"), a.array("items").toString()));

        mcp.tool("get_data_at",
                "Get detailed info about the data item at a specific address: "
                    + "type, size, label, value, and containing item info.")
            .string("address", "Address in hex")
            .program()
            .handler(a -> getDataAt(a.str("program"), a.str("address")));

        mcp.tool("apply_data_type", "Apply any fixed-length data type at an address without deleting instructions.")
            .string("address", "Address in hex")
            .string("data_type", "Data type name or expression")
            .optBoolean("clear_existing", true, "Clear conflicting data first")
            .optString("label", null, "Optional label")
            .program()
            .handler(a -> applyDataType(a.str("program"), a.str("address"), a.str("data_type"),
                a.bool("clear_existing"), emptyToNull(a.str("label"))));

    }

    String clearData(String programName, String addressStr, String sizeStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to clear data");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear data");
                boolean success = false;
                try {
                    Address start = program.getAddressFactory().getAddress(addressStr);
                    if (start == null) throw new IllegalArgumentException("Invalid address: " + addressStr);
                    Listing listing = program.getListing();

                    Address end;
                    if (sizeStr != null && !sizeStr.isEmpty()) {
                        int size = Integer.parseInt(sizeStr);
                        if (size <= 0) throw new IllegalArgumentException("Size must be positive");
                        end = start.add(size - 1);
                    } else {
                        Data data = listing.getDataAt(start);
                        if (data == null) {
                            data = listing.getDataContaining(start);
                        }
                        if (data != null) {
                            start = data.getMinAddress();
                            end = data.getMaxAddress();
                        } else {
                            result.set("No data defined at " + start);
                            return;
                        }
                    }

                    InstructionIterator instructions = listing.getInstructions(start, true);
                    if (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        if (instruction.getAddress().compareTo(end) <= 0) {
                            throw new IllegalArgumentException("Instruction at " + instruction.getAddress() +
                                " overlaps the range; clear_data never removes code");
                        }
                    }

                    listing.clearCodeUnits(start, end, false);
                    success = true;
                    result.set("Cleared data from " + start + " to " + end);
                } catch (Exception e) {
                    Msg.error(this, "Error clearing data", e);
                    result.set("Error clearing data: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            result.set("Clear data interrupted");
            Msg.error(this, "Clear data interrupted", e);
        } catch (InvocationTargetException e) {
            Msg.error(this, "Failed to execute clear data on Swing thread", e);
            result.set("Error clearing data: " + e.getMessage());
        }

        return result.get();
    }

    String defineDataBatch(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to define data batch");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();
            if (items.isEmpty()) return "Data batch must not be empty";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Define data batch");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Listing listing = program.getListing();
                    SymbolTable symTable = program.getSymbolTable();

                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String typeName = item.get("data_type").getAsString();
                        String label = item.has("label") ? item.get("label").getAsString() : null;

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            if (address == null) throw new IllegalArgumentException("Invalid address");
                            DataType dt = resolveDataType(dtm, typeName);
                            if (dt == null) throw new IllegalArgumentException("Unknown data type: " + typeName);
                            if (dt.getLength() <= 0) {
                                throw new IllegalArgumentException("Data type has no fixed positive length: " + typeName);
                            }
                            listing.createData(address, dt);

                            if (label != null && !label.isEmpty()) {
                                symTable.createLabel(address, label, SourceType.USER_DEFINED);
                            }
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = failed == 0 && succeeded == items.size();
                    result.set((success ? "Committed. " : "Rolled back. ") +
                        "Total: " + items.size() + ", Applied: " + succeeded +
                        ", Failed: " + failed +
                        (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in define data batch", e);
                    result.set("Error in batch: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            result.set("Error parsing JSON: " + e.getMessage());
        }

        return result.get();
    }

    String getDataAt(String programName, String addressStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Listing listing = program.getListing();

            Data data = listing.getDataAt(addr);
            String matchType = "exact";
            if (data == null) {
                data = listing.getDataContaining(addr);
                matchType = "containing";
            }

            if (data == null) {
                return "No data defined at " + addressStr;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Address: ").append(data.getAddress()).append("\n");
            sb.append("Match: ").append(matchType).append("\n");
            sb.append("Type: ").append(data.getDataType().getName()).append("\n");
            sb.append("Size: ").append(data.getLength()).append(" bytes\n");
            sb.append("Value: ").append(data.getDefaultValueRepresentation()).append("\n");

            Symbol[] symbols = program.getSymbolTable().getSymbols(data.getAddress());
            if (symbols.length > 0) {
                sb.append("Label: ").append(symbols[0].getName()).append("\n");
            }

            if ("containing".equals(matchType)) {
                long offset = addr.subtract(data.getAddress());
                sb.append("Offset within item: ").append(offset).append("\n");
            }

            return sb.toString();
        } catch (Exception e) {
            return "Error getting data: " + e.getMessage();
        }
    }

    String applyDataType(String programName, String addressStr, String dataTypeName,
                                 boolean clearExisting, String label) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (dataTypeName == null || dataTypeName.isBlank()) return "Data type is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to apply data type");
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply data type via HTTP");
                boolean success = false;
                try {
                    Address start = program.getAddressFactory().getAddress(addressStr);
                    if (start == null) throw new IllegalArgumentException("Invalid address: " + addressStr);
                    DataType dt = resolveDataType(program.getDataTypeManager(), dataTypeName);
                    if (dt == null) throw new IllegalArgumentException("Unknown data type: " + dataTypeName);
                    if (dt.getLength() <= 0) {
                        throw new IllegalArgumentException("Data type has no fixed positive length: " +
                            dt.getDisplayName());
                    }
                    Address end = start.add(dt.getLength() - 1L);
                    if (!program.getMemory().contains(start) || !program.getMemory().contains(end)) {
                        throw new IllegalArgumentException("Data type range " + start + " - " + end +
                            " is outside program memory");
                    }

                    Listing listing = program.getListing();
                    InstructionIterator instructions = listing.getInstructions(start, true);
                    if (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        if (instruction.getAddress().compareTo(end) <= 0) {
                            throw new IllegalArgumentException("Instruction at " + instruction.getAddress() +
                                " overlaps the target range; code is never cleared automatically");
                        }
                    }

                    if (clearExisting) listing.clearCodeUnits(start, end, false);
                    Data created = listing.createData(start, dt);
                    if (label != null && !label.isBlank()) {
                        program.getSymbolTable().createLabel(
                            start, label.trim(), SourceType.USER_DEFINED);
                    }
                    success = true;
                    result.set("Applied " + created.getDataType().getPathName() + " at " + start +
                        " (" + created.getLength() + " bytes)" +
                        (label == null || label.isBlank() ? "" : "; label: " + label.trim()));
                } catch (Exception e) {
                    Msg.error(this, "Error applying data type", e);
                    result.set("Error applying data type: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Apply data type interrupted";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "Error applying data type: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }
        return result.get();
    }
}
