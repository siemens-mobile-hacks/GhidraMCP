package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.data.DataTypeManager;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Function operations: decompile/disassemble, rename, prototypes, variables, create function, disassemble code. Part of the original GhidraMCP tool set. */
final class FunctionEditTools extends CoreTool {

    FunctionEditTools(McpEnvironment env, DecompilerService decompiler) {
        super(env, decompiler);
    }

    @Override
    void registerMcp(McpServer mcp) {
        mcp.tool("disassemble_code",
                "Disassemble code starting at an undefined address.\n\n"
                    + "mode may be \"auto\", \"arm\", or \"thumb\". ARM/Thumb mode uses Ghidra's "
                    + "architecture-specific disassembly command and sets the TMode context. "
                    + "Existing code or data is not cleared automatically.")
            .string("address", "Start address in hex")
            .optString("mode", "auto", "\"auto\", \"arm\" or \"thumb\"")
            .program()
            .handler(a -> disassembleCode(a.str("program"), a.str("address"), a.str("mode")));

        mcp.tool("create_function",
                "Create a function at an existing instruction. If disassemble_if_needed is true and "
                    + "no instruction exists, disassemble from the entry point first.\n\n"
                    + "If name is omitted, Ghidra keeps a suitable label at the entry point or assigns "
                    + "its default FUN_* name. The address must not be inside another function.")
            .string("address", "Entry point address in hex")
            .optString("name", null, "Optional function name")
            .optBoolean("disassemble_if_needed", false, "Disassemble an undefined entry point first")
            .program()
            .handler(a -> createFunction(a.str("program"), a.str("address"), emptyToNull(a.str("name")),
                a.bool("disassemble_if_needed")));

        mcp.tool("set_function_prototype", "Set a function's prototype.")
            .string("function_address", "Function address in hex")
            .string("prototype", "C prototype, e.g. \"int foo(char *buf, int len)\"")
            .optString("calling_convention", "",
                "Optional calling convention; empty keeps the function's current one")
            .optString("source_type", "user_defined", "Signature source type")
            .program()
            .handler(a -> setFunctionPrototypeReport(a.str("program"), a.str("function_address"),
                a.str("prototype"), a.str("calling_convention"), a.str("source_type")));

        mcp.tool("batch_rename_functions",
                "Rename multiple functions in one transaction. "
                    + "Each item: {\"address\": \"0x...\", \"new_name\": \"MyFunction\"}")
            .array("renames", McpServer.objectSchema("address", "string", "new_name", "string"),
                "Functions to rename")
            .program()
            .handler(a -> batchRenameFunctions(a.str("program"), a.array("renames").toString()));
    }

    String setFunctionPrototypeReport(String programName, String functionAddress,
            String prototype, String callingConvention, String sourceType) {
        PrototypeResult result = setFunctionPrototype(programName, functionAddress,
            prototype, callingConvention, sourceType);
        if (result.isSuccess()) {
            // Even with successful operations, include any warning messages for debugging
            String successMsg = "Function prototype set successfully";
            if (!result.getErrorMessage().isEmpty()) {
                successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
            }
            return successMsg;
        }
        return "Failed to set function prototype: " + result.getErrorMessage();
    }

    /**
     * Disassembles undefined bytes, with explicit ARM/Thumb context support.
     */
    String disassembleCode(String programName, String addressStr, String modeStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        String mode = modeStr == null || modeStr.isBlank()
            ? "auto" : modeStr.trim().toLowerCase(Locale.ROOT);
        if (!mode.equals("auto") && !mode.equals("arm") && !mode.equals("thumb")) {
            return "Invalid disassembly mode '" + modeStr + "'; expected auto, arm, or thumb";
        }

        Address requested;
        try {
            requested = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address '" + addressStr + "': " + e.getMessage();
        }
        if (requested == null) return "Invalid address: " + addressStr;

        Address start = requested;
        if (mode.equals("thumb")) {
            start = requested.getNewAddress(requested.getOffset() & ~1L);
        } else if (mode.equals("arm")) {
            start = requested.getNewAddress(requested.getOffset() & ~3L);
        }
        final Address disassemblyStart = start;

        if (!program.getMemory().contains(disassemblyStart)) {
            return "Address is not in program memory: " + disassemblyStart;
        }
        if ((mode.equals("arm") || mode.equals("thumb")) &&
                program.getProgramContext().getRegister("TMode") == null) {
            return "Program language " + program.getLanguageID() +
                " does not expose the ARM TMode context register";
        }

        AtomicReference<String> result = new AtomicReference<>("Failed to disassemble code");
        AtomicReference<DisassembleCommand> completedCommand = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Listing listing = program.getListing();
                    Instruction existing = listing.getInstructionAt(disassemblyStart);
                    if (existing != null) {
                        result.set("Instruction already defined at " + disassemblyStart +
                            ": " + existing);
                        return;
                    }

                    CodeUnit codeUnit = listing.getCodeUnitContaining(disassemblyStart);
                    if (isDefinedData(codeUnit)) {
                        result.set("Cannot disassemble at " + disassemblyStart +
                            ": defined data overlaps the address; clear it first");
                        return;
                    }

                    DisassembleCommand cmd = mode.equals("auto")
                        ? new DisassembleCommand(disassemblyStart, null, true)
                        : new ArmDisassembleCommand(disassemblyStart, null, mode.equals("thumb"));
                    // Keep this endpoint synchronous and deterministic. Incremental analysis can
                    // open follow-on transactions; callers only requested instruction creation.
                    cmd.enableCodeAnalysis(false);
                    if (!executeCommand(cmd, program)) {
                        String status = cmd.getStatusMsg();
                        result.set("Failed to disassemble at " + disassemblyStart +
                            (status == null || status.isEmpty() ? "" : ": " + status));
                        return;
                    }
                    completedCommand.set(cmd);
                } catch (Exception e) {
                    Msg.error(this, "Error disassembling code", e);
                    result.set("Error disassembling code: " + e.getMessage());
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Disassembly interrupted";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "Error disassembling code: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }

        DisassembleCommand cmd = completedCommand.get();
        if (cmd == null) return result.get();

        try {
            SwingUtilities.invokeAndWait(() -> {
                Instruction created = program.getListing().getInstructionAt(disassemblyStart);
                if (created == null) {
                    result.set("Failed to disassemble at " + disassemblyStart +
                        ": the transaction completed but no instruction persisted");
                    return;
                }
                result.set("Disassembled " + cmd.getDisassembledAddressSet().getNumAddresses() +
                    " byte(s) from " + disassemblyStart + " in " + mode +
                    " mode; first instruction: " + created);
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Disassembly interrupted while waiting for the transaction to commit";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "Error verifying disassembly: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }
        return result.get();
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    PrototypeResult setFunctionPrototype(String programName, String functionAddrStr,
                                                 String prototype, String callingConvention,
                                                 String sourceTypeStr) {
        // Input validation
        Program program = getProgramByName(programName);
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final SourceType sourceType;
        try {
            sourceType = parseSourceType(sourceTypeStr);
        } catch (IllegalArgumentException e) {
            return new PrototypeResult(false, e.getMessage());
        }

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, callingConvention,
                    sourceType, success, errorMessage));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            String msg = "Set function prototype interrupted";
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } catch (InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       String callingConvention, SourceType sourceType,
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // FunctionSignatureParser may select the program's default convention when the
            // declaration does not spell one out.  Preserve the existing convention unless
            // the caller explicitly asks to change it.
            String effectiveCallingConvention = callingConvention;
            if (effectiveCallingConvention == null || effectiveCallingConvention.isBlank()) {
                effectiveCallingConvention = func.getCallingConventionName();
            }

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(
                program, addr, func.getSignature(), prototype, effectiveCallingConvention, sourceType,
                success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    void parseFunctionSignatureAndApply(Program program, Address addr,
                                              ghidra.program.model.listing.FunctionSignature originalSignature,
                                              String prototype,
                                              String callingConvention, SourceType sourceType,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                env.dataTypeManagerService();

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig =
                parser.parse(originalSignature, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, sourceType);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                Function appliedFunction = program.getFunctionManager().getFunctionAt(addr);
                if (appliedFunction == null) {
                    throw new IllegalStateException("Function disappeared after applying signature");
                }
                if (callingConvention != null && !callingConvention.isBlank()) {
                    appliedFunction.setCallingConvention(
                        normalizeCallingConvention(callingConvention));
                }
                appliedFunction.setSignatureSource(sourceType);
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    SourceType parseSourceType(String sourceTypeStr) {
        if (sourceTypeStr == null || sourceTypeStr.isBlank()) return SourceType.USER_DEFINED;
        String normalized = sourceTypeStr.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        if (normalized.equals("USER")) normalized = "USER_DEFINED";
        try {
            return SourceType.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid source_type '" + sourceTypeStr +
                "'; expected default, analysis, ai, imported, or user_defined");
        }
    }

    String normalizeCallingConvention(String callingConvention) {
        String normalized = callingConvention.trim();
        if (normalized.equalsIgnoreCase("unknown")) {
            return Function.UNKNOWN_CALLING_CONVENTION_STRING;
        }
        if (normalized.equalsIgnoreCase("default")) {
            return Function.DEFAULT_CALLING_CONVENTION_STRING;
        }
        return normalized;
    }

    String batchRenameFunctions(String programName, String jsonBody) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to batch rename");

        try {
            JsonArray items = JsonParser.parseString(jsonBody).getAsJsonArray();
            if (items.isEmpty()) return "Rename batch must not be empty";

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch rename functions");
                boolean success = false;
                int succeeded = 0;
                int failed = 0;
                StringBuilder errors = new StringBuilder();

                try {
                    for (JsonElement el : items) {
                        JsonObject item = el.getAsJsonObject();
                        String addr = item.get("address").getAsString();
                        String newName = item.get("new_name").getAsString();

                        try {
                            Address address = program.getAddressFactory().getAddress(addr);
                            Function func = getFunctionForAddress(program, address);
                            if (func == null) {
                                failed++;
                                errors.append(addr).append(": No function at address\n");
                                continue;
                            }
                            func.setName(newName, SourceType.USER_DEFINED);
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
                    Msg.error(this, "Error in batch rename", e);
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

    /**
     * Creates a function at an instruction, optionally disassembling its entry point first.
     *
     * A label is only a symbol, so converting LAB_* into something the
     * decompiler can consume requires a real Function object.  CreateFunctionCmd
     * computes the function body using the same logic as Ghidra's Create
     * Function action.
     */
    String createFunction(String programName, String addressStr, String name,
            boolean disassembleIfNeeded) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address '" + addressStr + "': " + e.getMessage();
        }
        if (addr == null) return "Invalid address: " + addressStr;
        if (!program.getMemory().contains(addr)) return "Address is not in program memory: " + addr;

        String requestedName = (name == null || name.trim().isEmpty()) ? null : name.trim();

        FunctionManager initialFunctionManager = program.getFunctionManager();
        Function initialExisting = initialFunctionManager.getFunctionAt(addr);
        if (initialExisting != null) {
            return "Function already exists: " + initialExisting.getName() +
                " at " + initialExisting.getEntryPoint();
        }
        Function initialContaining = initialFunctionManager.getFunctionContaining(addr);
        if (initialContaining != null) {
            return "Cannot create function at " + addr +
                ": address is inside function " + initialContaining.getName() +
                " at " + initialContaining.getEntryPoint();
        }

        if (program.getListing().getInstructionAt(addr) == null && disassembleIfNeeded) {
            String disassemblyResult = disassembleCode(programName, addressStr, "auto");
            if (!disassemblyResult.startsWith("Disassembled ")) {
                return "Cannot create function at " + addr +
                    ": automatic disassembly failed: " + disassemblyResult;
            }
        }

        AtomicReference<String> result = new AtomicReference<>("Failed to create function");
        AtomicReference<CreateFunctionCmd> completedCommand = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    FunctionManager functionManager = program.getFunctionManager();
                    Function existing = functionManager.getFunctionAt(addr);
                    if (existing != null) {
                        result.set("Function already exists: " + existing.getName() +
                            " at " + existing.getEntryPoint());
                        return;
                    }

                    Function containing = functionManager.getFunctionContaining(addr);
                    if (containing != null) {
                        result.set("Cannot create function at " + addr +
                            ": address is inside function " + containing.getName() +
                            " at " + containing.getEntryPoint());
                        return;
                    }

                    if (program.getListing().getInstructionAt(addr) == null) {
                        result.set("Cannot create function at " + addr +
                            ": no instruction is defined at this address; disassemble it first");
                        return;
                    }

                    CreateFunctionCmd cmd = requestedName == null
                        ? new CreateFunctionCmd(addr)
                        : new CreateFunctionCmd(requestedName, addr, null, SourceType.USER_DEFINED);

                    if (!executeCommand(cmd, program)) {
                        String status = cmd.getStatusMsg();
                        result.set("Failed to create function at " + addr +
                            (status == null || status.isEmpty() ? "" : ": " + status));
                        return;
                    }
                    completedCommand.set(cmd);
                } catch (Exception e) {
                    Msg.error(this, "Error creating function", e);
                    result.set("Error creating function: " + e.getMessage());
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Msg.error(this, "Create function interrupted", e);
            return "Create function interrupted";
        } catch (InvocationTargetException e) {
            Msg.error(this, "Failed to execute create function on Swing thread", e);
            Throwable cause = e.getCause();
            return "Error creating function: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }

        if (completedCommand.get() == null) return result.get();

        try {
            SwingUtilities.invokeAndWait(() -> {
                Function created = program.getFunctionManager().getFunctionAt(addr);
                if (created == null) {
                    result.set("Failed to create function at " + addr +
                        ": the transaction completed but no function persisted");
                    return;
                }
                result.set("Function created: " + created.getName() + " at " +
                    created.getEntryPoint() + " (body " + created.getBody().getMinAddress() +
                    " - " + created.getBody().getMaxAddress() + ")");
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Function creation interrupted while waiting for the transaction to commit";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "Error verifying function creation: " +
                (cause != null && cause.getMessage() != null ? cause.getMessage() : e.getMessage());
        }

        return result.get();
    }
}
