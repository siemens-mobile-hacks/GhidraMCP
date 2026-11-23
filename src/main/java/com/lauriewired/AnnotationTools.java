package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Comments, data/label renaming and labels. Part of the original GhidraMCP tool set. */
final class AnnotationTools extends CoreTool {

    AnnotationTools(McpEnvironment env, DecompilerService decompiler) {
        super(env, decompiler);
    }

    @Override
    void registerMcp(McpServer mcp) {
        mcp.tool("batch_set_comments",
                "Set multiple comments in one transaction. comment_type: \"decompiler\" "
                    + "(PRE_COMMENT) or \"disassembly\" (EOL_COMMENT). "
                    + "Each comment: {\"address\": \"0x...\", \"comment\": \"text\"}")
            .array("comments", McpServer.objectSchema("address", "string", "comment", "string"),
                "Comments to set")
            .optString("comment_type", "decompiler", "\"decompiler\" or \"disassembly\"")
            .program()
            .handler(a -> batchSetComments(a.str("program"),
                a.object("comment_type", "comments").toString()));

        mcp.tool("create_label", "Create a label/symbol at any address (code, data, or undefined bytes).")
            .string("address", "Address in hex")
            .string("name", "Label name")
            .optString("namespace", null, "Optional namespace")
            .program()
            .handler(a -> createLabel(a.str("program"), a.str("address"), a.str("name"),
                emptyToNull(a.str("namespace"))));
    }

    String batchSetComments(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch set comments");

        try {
            JsonObject body = JsonParser.parseString(jsonBody).getAsJsonObject();
            String commentTypeStr = body.has("comment_type") ? body.get("comment_type").getAsString() : "decompiler";
            int commentType = "disassembly".equalsIgnoreCase(commentTypeStr)
                    ? CodeUnit.EOL_COMMENT : CodeUnit.PRE_COMMENT;
            JsonArray comments = body.getAsJsonArray("comments");
            if (comments == null || comments.isEmpty()) return "Comments batch must not be empty";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch set comments");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    Listing listing = program.getListing();

                    for (JsonElement el : comments) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String comment = item.get("comment").getAsString();

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            listing.setComment(address, commentType, comment);
                            succeeded++;
                        } catch (Exception e) {
                            failed++;
                            errors.append(addr).append(": ").append(e.getMessage()).append("\n");
                        }
                    }

                    success = failed == 0 && succeeded == comments.size();
                    result.set((success ? "Committed. " : "Rolled back. ") +
                        "Total: " + comments.size() + ", Applied: " + succeeded +
                        ", Failed: " + failed +
                        (errors.length() > 0 ? "\nErrors:\n" + errors : ""));
                } catch (Exception e) {
                    Msg.error(this, "Error in batch set comments", e);
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

    String createLabel(String programName, String addressStr, String name, String namespace) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (name == null || name.isEmpty()) return "Name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create label");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create label");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    SymbolTable symTable = program.getSymbolTable();

                    Namespace ns = null;
                    if (namespace != null && !namespace.isEmpty()) {
                        ns = symTable.getNamespace(namespace, null);
                        if (ns == null) {
                            ns = symTable.createNameSpace(null, namespace, SourceType.USER_DEFINED);
                        }
                    }

                    if (ns != null) {
                        symTable.createLabel(addr, name, ns, SourceType.USER_DEFINED);
                    } else {
                        symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                    }

                    success = true;
                    result.set("Label '" + name + "' created at " + addr);
                } catch (Exception e) {
                    Msg.error(this, "Error creating label", e);
                    result.set("Error creating label: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute create label on Swing thread", e);
        }

        return result.get();
    }
}
