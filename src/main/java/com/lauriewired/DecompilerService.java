package com.lauriewired;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * One decompiler process per program (instead of one per request) plus a
 * small LRU of results. Any change to the program clears its cache; closing
 * the program disposes the decompiler.
 */
final class DecompilerService {

    private static final int MAX_CACHED = 64;

    private final class Entry implements DomainObjectListener {
        final Program program;
        final DecompInterface ifc = new DecompInterface();
        boolean pcode = true;
        /** Program modification number the cached results belong to. */
        long modification = -1;
        final Map<String, DecompileResults> results = new LinkedHashMap<String, DecompileResults>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, DecompileResults> eldest) {
                return size() > MAX_CACHED;
            }
        };

        Entry(Program program) {
            this.program = program;
            DecompileOptions options = new DecompileOptions();
            options.grabFromProgram(program);
            ifc.setOptions(options);
            ifc.toggleSyntaxTree(true);
            if (!ifc.openProgram(program)) {
                String msg = ifc.getLastMessage();
                ifc.dispose();
                throw McpSupport.fail("Decompiler failed to start: " + msg);
            }
            program.addListener(this);
        }

        @Override
        public void domainObjectChanged(DomainObjectChangedEvent ev) {
            if (ev.contains(DomainObjectEvent.CLOSED)) {
                dispose(program);
                return;
            }
            // Staleness is detected via the modification number in decompile(); no locking
            // here, this runs on the Swing thread while a decompile may hold the entry lock.
        }

        void close() {
            program.removeListener(this);
            ifc.dispose();
        }
    }

    private final Map<Program, Entry> entries = new HashMap<>();
    private volatile long hits;
    private volatile long misses;

    private synchronized Entry entry(Program program) {
        Entry e = entries.get(program);
        if (e == null) {
            e = new Entry(program);
            entries.put(program, e);
        }
        return e;
    }

    /** Decompiles {@code function}; throws a tool error on failure or timeout. */
    DecompileResults decompile(Function function, int timeoutSeconds) {
        Program program = function.getProgram();
        Entry e = entry(program);
        synchronized (e) {
            long mod = program.getModificationNumber();
            if (mod != e.modification) {
                e.results.clear();
                e.modification = mod;
            }
            Address entryPoint = function.getEntryPoint();
            String key = entryPoint.toString();
            DecompileResults cached = e.results.get(key);
            if (cached != null) {
                hits++;
                return cached;
            }
            misses++;
            DecompileResults r = e.ifc.decompileFunction(function, Math.max(1, timeoutSeconds), TaskMonitor.DUMMY);
            if (r == null || !r.decompileCompleted()) {
                String why = r == null ? "no result" : r.isTimedOut()
                    ? "timed out after " + timeoutSeconds + " s; retry with a larger timeout"
                    : r.failedToStart() ? "decompiler failed to start" : r.getErrorMessage();
                throw McpSupport.fail("Decompilation of " + McpSupport.fqn(function) + " failed: " + why);
            }
            if (program.getModificationNumber() == mod) {
                e.results.put(key, r);
            }
            return r;
        }
    }

    synchronized void dispose(Program program) {
        Entry e = entries.remove(program);
        if (e != null) e.close();
    }

    synchronized void disposeAll() {
        for (Entry e : entries.values()) e.close();
        entries.clear();
    }

    synchronized String stats() {
        return "decompiler processes=" + entries.size() + ", cache hits=" + hits + ", misses=" + misses;
    }
}
