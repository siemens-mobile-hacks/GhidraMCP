package com.lauriewired;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/** Memory reading in several formats, writing, searching, listings and segments. */
final class MemoryTools {

    private static final int MAX_READ = 1 << 20;

    private final McpEnvironment env;

    MemoryTools(McpEnvironment env) {
        this.env = env;
    }

    void register(McpServer mcp) {
        mcp.tool("read_bytes",
                "Read raw bytes from memory. format: hex (default, contiguous hex string), hexdump "
                    + "(offset, hex and ASCII columns), base64 or ascii (non-printable bytes as '.').")
            .string("address", "Start address")
            .integer("length", "Number of bytes (max 1 MiB)")
            .optString("format", "hex", "hex, hexdump, base64 or ascii")
            .program()
            .handler(this::read);

        mcp.tool("write_bytes",
                "Patch initialized program memory. Refuses ranges that overlap "
                    + "instructions unless clear_code=true (they are cleared first, then the bytes "
                    + "are written); defined data in the range is kept. The written bytes are read "
                    + "back and verified.")
            .string("address", "Start address")
            .string("bytes", "Bytes to write, in the given format")
            .optString("format", "hex", "hex (\"90 90\" or \"9090\") or base64")
            .optBoolean("clear_code", false, "Clear overlapping instructions first")
            .program()
            .handler(this::write);

        mcp.tool("search_memory",
                "Search initialized memory. kind: hex (exact bytes, \"DEADBEEF\" or \"de ad be ef\"), "
                    + "string (ASCII), utf16le, utf16be, or value (an integer of width 1/2/4/8 bytes in "
                    + "the program's endianness unless endian is given). For masked/bit patterns use "
                    + "search_instruction_pattern.")
            .string("query", "What to search for")
            .optString("kind", "hex", "hex, string, utf16le, utf16be or value")
            .optInteger("width", 4, "Byte width for kind=value")
            .optString("endian", "", "little or big (kind=value; default: program endianness)")
            .optString("start_address", "", "Start of the search range")
            .optString("end_address", "", "End of the search range")
            .optInteger("limit", 100, "Maximum number of matches")
            .program()
            .handler(this::search);

        mcp.tool("get_listing",
                "The code listing for an address range without modifying anything: instructions, "
                    + "defined data and undefined bytes, with labels and EOL comments.")
            .string("start_address", "Start address")
            .optString("end_address", "", "End address (inclusive)")
            .optInteger("max_units", 200, "Maximum number of code units")
            .program()
            .handler(this::listing);

        mcp.tool("list_segments",
                "List memory blocks: name, range, size, permissions (rwx, volatile), type, "
                    + "initialized/overlay flags and source.")
            .optInteger("offset", 0, "Pagination offset")
            .optInteger("limit", 100, "Maximum number of blocks")
            .program()
            .handler(this::segments);
    }

    // ------------------------------------------------------------------

    private String read(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Address addr = McpSupport.address(p, a.str("address"));
        int length = a.integer("length");
        if (length <= 0 || length > MAX_READ) throw McpSupport.fail("length must be between 1 and " + MAX_READ);
        byte[] bytes = new byte[length];
        int got;
        try {
            got = p.getMemory().getBytes(addr, bytes);
        }
        catch (MemoryAccessException e) {
            throw McpSupport.fail("Cannot read " + length + " bytes at " + addr + ": " + e.getMessage());
        }
        if (got < length) {
            byte[] shorter = new byte[got];
            System.arraycopy(bytes, 0, shorter, 0, got);
            bytes = shorter;
        }
        String format = a.str("format").trim().toLowerCase(Locale.ROOT);
        String suffix = got < length ? "\n-- only " + got + " of " + length + " bytes readable --" : "";
        switch (format) {
            case "hex":
                return toHex(bytes) + suffix;
            case "base64":
                return Base64.getEncoder().encodeToString(bytes) + suffix;
            case "ascii": {
                StringBuilder sb = new StringBuilder();
                for (byte b : bytes) sb.append(b >= 32 && b < 127 ? (char) b : '.');
                return sb + suffix;
            }
            case "hexdump":
                return hexdump(addr, bytes) + suffix;
            default:
                throw McpSupport.fail("format must be hex, hexdump, base64 or ascii");
        }
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private static String hexdump(Address start, byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 16) {
            sb.append(start.add(i)).append("  ");
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < bytes.length) {
                    byte b = bytes[i + j];
                    sb.append(String.format("%02x ", b & 0xff));
                    ascii.append(b >= 32 && b < 127 ? (char) b : '.');
                }
                else {
                    sb.append("   ");
                }
                if (j == 7) sb.append(' ');
            }
            sb.append(" |").append(ascii).append("|\n");
        }
        return sb.toString().trim();
    }

    static byte[] parseHex(String text) {
        String t = text.replaceAll("(?i)0x", "").replaceAll("[\\s,:]", "");
        if (t.isEmpty() || t.length() % 2 != 0) throw McpSupport.fail("Hex must contain an even number of digits");
        byte[] out = new byte[t.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(t.charAt(2 * i), 16);
            int lo = Character.digit(t.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw McpSupport.fail("Invalid hex digit near position " + (2 * i));
            out[i] = (byte) (hi << 4 | lo);
        }
        return out;
    }

    private String write(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Address addr = McpSupport.address(p, a.str("address"));
        String format = a.str("format").trim().toLowerCase(Locale.ROOT);
        byte[] bytes;
        if (format.equals("hex")) {
            bytes = parseHex(a.str("bytes"));
        }
        else if (format.equals("base64")) {
            try {
                bytes = Base64.getDecoder().decode(a.str("bytes").trim());
            }
            catch (IllegalArgumentException e) {
                throw McpSupport.fail("Invalid base64: " + e.getMessage());
            }
        }
        else {
            throw McpSupport.fail("format must be hex or base64");
        }
        if (bytes.length == 0) throw McpSupport.fail("No bytes to write");
        Address last = addr.add(bytes.length - 1);
        Memory mem = p.getMemory();
        MemoryBlock block = mem.getBlock(addr);
        if (block == null || !block.contains(last)) {
            throw McpSupport.fail("Range " + addr + "-" + last + " is not inside one memory block");
        }
        if (!block.isInitialized()) throw McpSupport.fail("Block " + block.getName() + " is not initialized");
        boolean clear = a.bool("clear_code");
        byte[] data = bytes;
        McpSupport.write(p, "Write bytes", () -> {
            AddressSet range = new AddressSet(addr, last);
            boolean hasCode = p.getListing().getInstructions(range, true).hasNext();
            if (hasCode && !clear) {
                throw McpSupport.fail("Instructions overlap " + addr + "-" + last + "; pass clear_code=true");
            }
            if (hasCode) {
                Instruction first = p.getListing().getInstructionContaining(addr);
                Address from = first != null ? first.getAddress() : addr;
                Instruction lastIns = p.getListing().getInstructionContaining(last);
                Address to = lastIns != null ? lastIns.getMaxAddress() : last;
                p.getListing().clearCodeUnits(from, to, false);
            }
            try {
                mem.setBytes(addr, data);
            }
            catch (MemoryAccessException e) {
                throw McpSupport.fail("Write failed: " + e.getMessage());
            }
            byte[] check = new byte[data.length];
            try {
                mem.getBytes(addr, check);
            }
            catch (MemoryAccessException e) {
                throw McpSupport.fail("Verification read failed: " + e.getMessage());
            }
            if (!java.util.Arrays.equals(check, data)) {
                throw McpSupport.fail("Verification failed: memory did not keep the written bytes");
            }
            return null;
        });
        return "Wrote " + bytes.length + " byte(s) at " + addr + ": " + toHex(bytes)
            + (clear ? " (overlapping code cleared)" : "");
    }

    private byte[] pattern(Program p, McpServer.Args a) {
        String q = a.str("query");
        String kind = a.str("kind").trim().toLowerCase(Locale.ROOT);
        switch (kind) {
            case "hex":
                return parseHex(q);
            case "string":
                return q.getBytes(StandardCharsets.ISO_8859_1);
            case "utf16le":
                return q.getBytes(StandardCharsets.UTF_16LE);
            case "utf16be":
                return q.getBytes(StandardCharsets.UTF_16BE);
            case "value": {
                long v = CodeAnalysisTools.parseValue(q);
                int width = a.integer("width");
                if (width != 1 && width != 2 && width != 4 && width != 8) throw McpSupport.fail("width must be 1, 2, 4 or 8");
                String endian = a.str("endian").trim().toLowerCase(Locale.ROOT);
                boolean big = endian.isEmpty() ? p.getLanguage().isBigEndian() : endian.equals("big");
                if (!endian.isEmpty() && !endian.equals("big") && !endian.equals("little")) {
                    throw McpSupport.fail("endian must be little or big");
                }
                byte[] out = new byte[width];
                for (int i = 0; i < width; i++) {
                    int shift = 8 * (big ? width - 1 - i : i);
                    out[i] = (byte) (v >>> shift);
                }
                return out;
            }
            default:
                throw McpSupport.fail("kind must be hex, string, utf16le, utf16be or value");
        }
    }

    private String search(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        byte[] pat = pattern(p, a);
        if (pat.length == 0) throw McpSupport.fail("Empty search pattern");
        Memory mem = p.getMemory();
        Address start = a.str("start_address").isEmpty() ? mem.getMinAddress() : McpSupport.address(p, a.str("start_address"));
        Address end = a.str("end_address").isEmpty() ? mem.getMaxAddress() : McpSupport.address(p, a.str("end_address"));
        int limit = Math.max(1, a.integer("limit"));
        List<String> lines = new ArrayList<>();
        Address cur = start;
        boolean more = false;
        while (cur != null && cur.compareTo(end) <= 0) {
            Address found = mem.findBytes(cur, end, pat, null, true, TaskMonitor.DUMMY);
            if (found == null) break;
            if (lines.size() >= limit) {
                more = true;
                break;
            }
            Function f = p.getFunctionManager().getFunctionContaining(found);
            Symbol s = p.getSymbolTable().getPrimarySymbol(found);
            MemoryBlock b = mem.getBlock(found);
            lines.add(found + (b == null ? "" : " [" + b.getName() + "]")
                + (s == null ? "" : " " + McpSupport.fqn(s))
                + (f == null ? "" : " in " + McpSupport.fqn(f)));
            try {
                cur = found.add(1);
            }
            catch (Exception e) {
                break;
            }
        }
        if (lines.isEmpty()) return "No matches for " + toHex(pat);
        return "Matches for " + toHex(pat) + ":\n" + String.join("\n", lines)
            + (more ? "\n-- more matches beyond limit " + limit + " --" : "");
    }

    private String listing(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        Address start = McpSupport.address(p, a.str("start_address"));
        Address end = a.str("end_address").isEmpty() ? null : McpSupport.address(p, a.str("end_address"));
        int max = Math.max(1, a.integer("max_units"));
        return McpSupport.onSwing(() -> {
            Listing listing = p.getListing();
            CodeUnitIterator it = listing.getCodeUnits(start, true);
            StringBuilder sb = new StringBuilder();
            int n = 0;
            while (it.hasNext()) {
                CodeUnit cu = it.next();
                if (end != null && cu.getMinAddress().compareTo(end) > 0) break;
                if (n++ >= max) {
                    sb.append("-- stopped at max_units ").append(max).append("; continue from ")
                        .append(cu.getMinAddress()).append(" --");
                    break;
                }
                Symbol label = p.getSymbolTable().getPrimarySymbol(cu.getMinAddress());
                if (label != null) sb.append(McpSupport.fqn(label)).append(":\n");
                sb.append("  ").append(cu.getMinAddress()).append("  ");
                StringBuilder hex = new StringBuilder();
                try {
                    byte[] b = cu.getBytes();
                    for (int i = 0; i < Math.min(b.length, 8); i++) hex.append(String.format("%02x", b[i] & 0xff));
                    if (b.length > 8) hex.append("..");
                }
                catch (MemoryAccessException e) {
                    hex.append("??");
                }
                sb.append(String.format("%-18s ", hex));
                if (cu instanceof Instruction) {
                    sb.append(cu);
                }
                else {
                    Data d = (Data) cu;
                    sb.append(d.isDefined() ? d.getDataType().getDisplayName() + " " + d.getDefaultValueRepresentation()
                        : "?? (undefined)");
                }
                String eol = cu.getComment(ghidra.program.model.listing.CommentType.EOL);
                if (eol != null) sb.append("  ; ").append(eol);
                sb.append('\n');
            }
            return sb.length() == 0 ? "No code units from " + start : sb.toString().trim();
        });
    }

    private String segments(McpServer.Args a) {
        Program p = McpSupport.program(env, a.str("program"));
        List<String> lines = new ArrayList<>();
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            String perms = (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-")
                + (b.isVolatile() ? "v" : "");
            lines.add(String.format("%s: %s - %s  size=0x%x  %s  %s%s%s%s", b.getName(), b.getStart(), b.getEnd(),
                b.getSize(), perms, b.getType(), b.isInitialized() ? " initialized" : " uninitialized",
                b.isOverlay() ? " overlay" : "",
                b.getSourceName() == null || b.getSourceName().isEmpty() ? "" : "  source=" + b.getSourceName()));
        }
        return McpSupport.page(lines, a.integer("offset"), a.integer("limit"));
    }
}
