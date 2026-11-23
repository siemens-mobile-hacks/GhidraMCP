package com.lauriewired;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;

/** Decompilation and function disassembly with paging, timeouts and caching. */
final class DecompilerTools {

    private final McpEnvironment env;
    private final DecompilerService decompiler;

    DecompilerTools(McpEnvironment env, DecompilerService decompiler) {
        this.env = env;
        this.decompiler = decompiler;
    }

    private static final String DECOMPILE_NOTES =
        " Results are cached per function until the program changes. Use start_line/end_line or "
            + "max_lines for long functions (lines are numbered then). "
            + "include_pcode=true appends the high P-code operations.";

    void register(McpServer mcp) {
        McpServer.ToolBuilder decompile = mcp.tool("decompile_function",
                "Decompile a function by name (qualified names like A::B::f accepted) or by an address "
                    + "at or inside it, and return the C code." + DECOMPILE_NOTES)
            .optString("name", "", "Function name")
            .optString("address", "", "Entry point or any address inside the function");
        decompileOptions(decompile).handler(a -> {
            Program p = McpSupport.program(env, a.str("program"));
            return decompile(McpSupport.function(p, a.str("name"), a.str("address")), a);
        });

        mcp.tool("disassemble_function",
                "Get assembly code (address: instruction; comment) for the function at or containing an "
                    + "address. Supports paging with offset/limit (limit 0 = all) and raw bytes.")
            .string("address", "Function entry or any address inside it")
            .optInteger("offset", 0, "Number of instructions to skip")
            .optInteger("limit", 0, "Maximum number of instructions (0 = all)")
            .optBoolean("show_bytes", false, "Include instruction bytes")
            .program()
            .handler(a -> {
                Program p = McpSupport.program(env, a.str("program"));
                Function f = McpSupport.function(p, null, a.str("address"));
                return disassemble(f, a.integer("offset"), a.integer("limit"), a.bool("show_bytes"));
            });
    }

    private static McpServer.ToolBuilder decompileOptions(McpServer.ToolBuilder b) {
        return b.optInteger("timeout", 60, "Decompiler timeout in seconds")
            .optInteger("start_line", null, "First line to return (1-based)")
            .optInteger("end_line", null, "Last line to return (inclusive)")
            .optInteger("max_lines", null, "Maximum number of lines to return")
            .optBoolean("include_pcode", false, "Append high P-code operations")
            .program();
    }

    private String decompile(Function f, McpServer.Args a) {
        DecompileResults r = decompiler.decompile(f, a.integer("timeout"));
        String c = r.getDecompiledFunction() == null ? "" : r.getDecompiledFunction().getC();
        Integer start = a.optInteger("start_line");
        Integer end = a.optInteger("end_line");
        Integer max = a.optInteger("max_lines");
        String out = c;
        if (start != null || end != null || max != null) {
            String[] lines = c.split("\n", -1);
            int total = lines.length;
            if (total > 0 && lines[total - 1].isEmpty()) total--;
            int from = Math.max(1, start == null ? 1 : start);
            int to = Math.min(total, end == null ? total : end);
            if (max != null && max > 0) to = Math.min(to, from + max - 1);
            if (from > total) {
                throw McpSupport.fail("start_line " + from + " is past the end (" + total + " lines)");
            }
            StringBuilder sb = new StringBuilder();
            int width = String.valueOf(total).length();
            for (int i = from; i <= to; i++) {
                sb.append(String.format("%" + width + "d: %s%n", i, lines[i - 1]));
            }
            sb.append("-- lines ").append(from).append('-').append(to).append(" of ").append(total);
            if (to < total) sb.append("; next start_line ").append(to + 1);
            sb.append(" --");
            out = sb.toString();
        }
        if (a.bool("include_pcode")) {
            out = out + "\n--- P-code (" + f.getName() + ") ---\n" + pcode(r.getHighFunction());
        }
        return out;
    }

    private static String pcode(HighFunction hf) {
        if (hf == null) return "(no high function)";
        StringBuilder sb = new StringBuilder();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            sb.append(op.getSeqnum().getTarget()).append(": ").append(op).append('\n');
        }
        return sb.toString().trim();
    }

    private String disassemble(Function f, int offset, int limit, boolean showBytes) {
        return McpSupport.onSwing(() -> {
            Program program = f.getProgram();
            Listing listing = program.getListing();
            AddressSetView body = f.getBody();
            List<String> lines = new ArrayList<>();
            InstructionIterator it = listing.getInstructions(body, true);
            while (it.hasNext()) {
                Instruction instr = it.next();
                String comment = listing.getComment(CommentType.EOL, instr.getAddress());
                StringBuilder line = new StringBuilder();
                line.append(instr.getAddress()).append(": ");
                if (showBytes) {
                    StringBuilder hex = new StringBuilder();
                    for (byte b : instr.getBytes()) hex.append(String.format("%02x", b & 0xff));
                    line.append(String.format("%-16s ", hex));
                }
                line.append(instr);
                if (comment != null) line.append(" ; ").append(comment);
                lines.add(line.toString());
            }
            if (offset == 0 && limit <= 0) return String.join("\n", lines);
            return McpSupport.page(lines, offset, limit);
        });
    }
}
