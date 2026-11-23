package com.lauriewired;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData;
import ghidra.app.plugin.core.instructionsearch.model.OperandMetadata;
import ghidra.program.model.lang.OperandType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/** Bit-accurate instruction pattern creation and search. Part of the original GhidraMCP tool set. */
final class InstructionPatternTools extends CoreTool {

    InstructionPatternTools(McpEnvironment env, DecompilerService decompiler) {
        super(env, decompiler);
    }

    @Override
    void registerMcp(McpServer mcp) {
        mcp.tool("create_instruction_pattern",
                "Create a bit-accurate pattern from contiguous instructions at address.\n\n"
                    + "Exact bytes use hex (\"D8\"), full wildcards use \"??\", and partially masked "
                    + "bytes use Ghidra-style bit expressions such as \"[1001....]\". mask_operands "
                    + "masks every operand and takes precedence over the more selective mask_scalars "
                    + "and mask_addresses options. masked_operands selects individual operands as "
                    + "\"instruction_index:operand_index\" (zero-based), for example [\"0:1\", \"2:0\"].")
            .string("address", "Address of the first instruction")
            .optInteger("instruction_count", 1, "Number of contiguous instructions")
            .optBoolean("mask_operands", false, "Mask every operand")
            .optBoolean("mask_scalars", false, "Mask scalar operands")
            .optBoolean("mask_addresses", false, "Mask address operands")
            .optArray("masked_operands", McpServer.schema("string", null),
                "Operands to mask as \"instruction_index:operand_index\"")
            .program()
            .handler(a -> createInstructionPattern(a.str("program"), a.str("address"),
                a.integer("instruction_count"), a.bool("mask_operands"), a.bool("mask_scalars"),
                a.bool("mask_addresses"), joinStrings(a.array("masked_operands"), ",")));

        mcp.tool("search_instruction_pattern",
                "Search loaded, initialized memory for an instruction pattern.\n\n"
                    + "Accepts patterns produced by create_instruction_pattern plus exact hex bytes, "
                    + "\"??\", nibble wildcards such as \"A?\"/\"?F\", and bit expressions such as "
                    + "\"[10..01..]\". Results are match start addresses; matches may be in undefined "
                    + "bytes and may overlap.")
            .string("pattern", "Pattern to search for")
            .optString("start_address", "", "Optional start of the search range")
            .optString("end_address", "", "Optional end of the search range")
            .optInteger("limit", 100, "Maximum number of matches")
            .program()
            .handler(a -> searchInstructionPattern(a.str("program"), a.str("pattern"),
                a.str("start_address"), a.str("end_address"), a.integer("limit")));
    }

    /**
     * Builds a bit-accurate Ghidra instruction pattern. Exact bytes are rendered as hex,
     * completely masked bytes as ??, and partial bytes as an eight-bit bracket expression.
     */
    String createInstructionPattern(String programName, String addressStr,
            int instructionCount, boolean maskOperands, boolean maskScalars,
            boolean maskAddresses, String maskedOperandsStr) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "Address is required";
        if (instructionCount <= 0 || instructionCount > 1000) {
            return "Instruction count must be between 1 and 1000";
        }

        Address start;
        try {
            start = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address '" + addressStr + "': " + e.getMessage();
        }
        if (start == null) return "Invalid address: " + addressStr;

        Listing listing = program.getListing();
        Instruction instruction = listing.getInstructionAt(start);
        if (instruction == null) {
            return "No instruction is defined at " + start;
        }

        Address end = instruction.getMaxAddress();
        for (int i = 1; i < instructionCount; i++) {
            Address expected = end.next();
            Instruction next = listing.getInstructionAfter(instruction.getAddress());
            if (expected == null || next == null || !next.getAddress().equals(expected)) {
                return "Only " + i + " contiguous instruction(s) are defined from " + start;
            }
            instruction = next;
            end = instruction.getMaxAddress();
        }

        try {
            InstructionSearchData searchData = new InstructionSearchData();
            searchData.load(program, new AddressRangeImpl(start, end));
            if (searchData.getInstructions().size() != instructionCount) {
                return "Ghidra parsed " + searchData.getInstructions().size() + " of " +
                    instructionCount + " selected instruction(s); pattern was not created";
            }
            if (maskOperands) {
                searchData.maskAllOperands();
            } else {
                if (maskScalars) searchData.maskOperandsByType(OperandType.SCALAR);
                if (maskAddresses) searchData.maskOperandsByType(OperandType.ADDRESS);
            }
            applySelectiveOperandMasks(searchData, maskedOperandsStr);

            String binaryPattern = searchData.getCombinedString();
            String pattern = formatInstructionPattern(binaryPattern);
            // Validate the generated representation before returning it to another MCP call.
            parseInstructionPattern(pattern);
            return pattern;
        } catch (Exception e) {
            Msg.error(this, "Error creating instruction pattern", e);
            return "Error creating instruction pattern: " + e.getMessage();
        }
    }

    static void applySelectiveOperandMasks(InstructionSearchData searchData,
            String selectorsStr) {
        List<int[]> selectors = parseOperandSelectors(selectorsStr);
        List<InstructionMetadata> instructions = searchData.getInstructions();
        for (int[] selector : selectors) {
            int instructionIndex = selector[0];
            int operandIndex = selector[1];
            if (instructionIndex >= instructions.size()) {
                throw new IllegalArgumentException("Instruction index " + instructionIndex +
                    " is out of range; pattern contains " + instructions.size() + " instruction(s)");
            }
            List<OperandMetadata> operands = instructions.get(instructionIndex).getOperands();
            if (operandIndex >= operands.size()) {
                throw new IllegalArgumentException("Operand index " + operandIndex +
                    " is out of range for instruction " + instructionIndex +
                    "; it has " + operands.size() + " operand(s)");
            }
            operands.get(operandIndex).setMasked(true);
        }
    }

    static List<int[]> parseOperandSelectors(String selectorsStr) {
        List<int[]> selectors = new ArrayList<>();
        if (selectorsStr == null || selectorsStr.isBlank()) return selectors;

        Set<String> seen = new HashSet<>();
        for (String rawSelector : selectorsStr.split(",")) {
            String selector = rawSelector.trim();
            if (!selector.matches("[0-9]+:[0-9]+")) {
                throw new IllegalArgumentException("Invalid operand selector '" + rawSelector +
                    "'; expected instruction_index:operand_index");
            }
            String[] parts = selector.split(":", 2);
            int instructionIndex;
            int operandIndex;
            try {
                instructionIndex = Integer.parseInt(parts[0]);
                operandIndex = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Operand selector is too large: " + selector);
            }
            if (seen.add(instructionIndex + ":" + operandIndex)) {
                selectors.add(new int[] { instructionIndex, operandIndex });
            }
        }
        return selectors;
    }

    /** Searches loaded and initialized memory for a bit-masked instruction pattern. */
    String searchInstructionPattern(String programName, String pattern,
            String startAddressStr, String endAddressStr, int limit) {
        Program program = getProgramByName(programName);
        if (program == null) return "No program loaded";
        if (limit <= 0 || limit > 10000) return "Limit must be between 1 and 10000";

        ParsedInstructionPattern parsed;
        try {
            parsed = parseInstructionPattern(pattern);
        } catch (IllegalArgumentException e) {
            return "Invalid instruction pattern: " + e.getMessage();
        }

        Address requestedStart = null;
        Address requestedEnd = null;
        try {
            if (startAddressStr != null && !startAddressStr.isBlank()) {
                requestedStart = program.getAddressFactory().getAddress(startAddressStr);
                if (requestedStart == null) return "Invalid start address: " + startAddressStr;
            }
            if (endAddressStr != null && !endAddressStr.isBlank()) {
                requestedEnd = program.getAddressFactory().getAddress(endAddressStr);
                if (requestedEnd == null) return "Invalid end address: " + endAddressStr;
            }
        } catch (Exception e) {
            return "Invalid search address: " + e.getMessage();
        }
        if (requestedStart != null && requestedEnd != null &&
                !requestedStart.getAddressSpace().equals(requestedEnd.getAddressSpace())) {
            return "Start and end addresses must be in the same address space";
        }
        if (requestedStart != null && requestedEnd != null &&
                requestedStart.compareTo(requestedEnd) > 0) {
            return "Start address must not be after end address";
        }

        List<String> matches = new ArrayList<>();
        AddressRangeIterator ranges = program.getMemory().getLoadedAndInitializedAddressSet()
            .getAddressRanges();
        TaskMonitor monitor = new ConsoleTaskMonitor();

        while (ranges.hasNext() && matches.size() < limit) {
            AddressRange range = ranges.next();
            Address rangeStart = range.getMinAddress();
            Address rangeEnd = range.getMaxAddress();
            if (requestedStart != null) {
                if (!rangeStart.getAddressSpace().equals(requestedStart.getAddressSpace())) continue;
                if (rangeEnd.compareTo(requestedStart) < 0) continue;
                if (rangeStart.compareTo(requestedStart) < 0) rangeStart = requestedStart;
            }
            if (requestedEnd != null) {
                if (!rangeStart.getAddressSpace().equals(requestedEnd.getAddressSpace())) continue;
                if (rangeStart.compareTo(requestedEnd) > 0) continue;
                if (rangeEnd.compareTo(requestedEnd) > 0) rangeEnd = requestedEnd;
            }

            Address cursor = rangeStart;
            while (cursor != null && cursor.compareTo(rangeEnd) <= 0 && matches.size() < limit) {
                Address match = program.getMemory().findBytes(cursor, rangeEnd,
                    parsed.value, parsed.mask, true, monitor);
                if (match == null) break;
                try {
                    Address matchEnd = match.addNoWrap(parsed.value.length - 1L);
                    if (matchEnd.compareTo(rangeEnd) > 0) break;
                } catch (AddressOverflowException e) {
                    break;
                }
                matches.add(match.toString());
                cursor = match.next(); // Preserve overlapping matches.
            }
        }

        return matches.isEmpty() ? "No matches" : String.join("\n", matches);
    }

    static String formatInstructionPattern(String binaryPattern) {
        if (binaryPattern == null) throw new IllegalArgumentException("Pattern is null");
        String bits = binaryPattern.replaceAll("\\s", "");
        if (bits.isEmpty() || bits.length() % 8 != 0 || !bits.matches("[01.]+")) {
            throw new IllegalArgumentException("Binary pattern must contain complete 8-bit bytes");
        }

        List<String> tokens = new ArrayList<>();
        for (int offset = 0; offset < bits.length(); offset += 8) {
            String token = bits.substring(offset, offset + 8);
            if (token.equals("........")) {
                tokens.add("??");
            } else if (!token.contains(".")) {
                tokens.add(String.format("%02X", Integer.parseInt(token, 2)));
            } else if (!token.substring(0, 4).contains(".") &&
                    token.substring(4).equals("....")) {
                tokens.add(Integer.toHexString(Integer.parseInt(token.substring(0, 4), 2))
                    .toUpperCase(Locale.ROOT) + "?");
            } else if (token.substring(0, 4).equals("....") &&
                    !token.substring(4).contains(".")) {
                tokens.add("?" + Integer.toHexString(Integer.parseInt(token.substring(4), 2))
                    .toUpperCase(Locale.ROOT));
            } else {
                tokens.add("[" + token + "]");
            }
        }
        return String.join(" ", tokens);
    }

    static ParsedInstructionPattern parseInstructionPattern(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            throw new IllegalArgumentException("Pattern is required");
        }

        List<Byte> values = new ArrayList<>();
        List<Byte> masks = new ArrayList<>();
        for (String rawToken : pattern.trim().split("\\s+")) {
            String token = rawToken.toUpperCase(Locale.ROOT);
            if (token.matches("[0-9A-F]+") && token.length() % 2 == 0) {
                for (int i = 0; i < token.length(); i += 2) {
                    values.add((byte) Integer.parseInt(token.substring(i, i + 2), 16));
                    masks.add((byte) 0xff);
                }
                continue;
            }

            if (token.matches("[0-9A-F?]{2}")) {
                int value = 0;
                int mask = 0;
                if (token.charAt(0) != '?') {
                    value |= Character.digit(token.charAt(0), 16) << 4;
                    mask |= 0xf0;
                }
                if (token.charAt(1) != '?') {
                    value |= Character.digit(token.charAt(1), 16);
                    mask |= 0x0f;
                }
                values.add((byte) value);
                masks.add((byte) mask);
                continue;
            }

            if (token.matches("\\[[01.]{8}\\]")) {
                int value = 0;
                int mask = 0;
                String bitToken = token.substring(1, 9);
                for (int i = 0; i < 8; i++) {
                    char bit = bitToken.charAt(i);
                    int shift = 7 - i;
                    if (bit != '.') mask |= 1 << shift;
                    if (bit == '1') value |= 1 << shift;
                }
                values.add((byte) value);
                masks.add((byte) mask);
                continue;
            }

            throw new IllegalArgumentException("Unsupported token '" + rawToken + "'");
        }

        byte[] valueArray = new byte[values.size()];
        byte[] maskArray = new byte[masks.size()];
        boolean hasFixedBit = false;
        for (int i = 0; i < values.size(); i++) {
            valueArray[i] = values.get(i);
            maskArray[i] = masks.get(i);
            hasFixedBit |= maskArray[i] != 0;
        }
        if (valueArray.length == 0) throw new IllegalArgumentException("Pattern is empty");
        if (!hasFixedBit) throw new IllegalArgumentException("Pattern cannot be entirely wildcarded");
        return new ParsedInstructionPattern(valueArray, maskArray);
    }

    static final class ParsedInstructionPattern {
        final byte[] value;
        final byte[] mask;

        ParsedInstructionPattern(byte[] value, byte[] mask) {
            this.value = value;
            this.mask = mask;
        }
    }
}
