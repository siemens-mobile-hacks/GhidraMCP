package com.lauriewired;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Entry point for running the GhidraMCP server without a GUI, e.g. from
 * {@code analyzeHeadless ... -postScript StartGhidraMcpServer.java}.
 */
public final class GhidraMcpHeadless {

    private static volatile CountDownLatch stopSignal;

    private GhidraMcpHeadless() {
    }

    /**
     * Starts the server for {@code project}, registers {@code program} (may be
     * null) as the initial current program and blocks until shutdown_ghidra is
     * called or the monitor is cancelled.
     */
    public static void serve(Project project, Program program, String host, int port,
            TaskMonitor monitor) throws Exception {
        Object owner = new Object();
        McpRuntime runtime = McpRuntime.acquire(owner, host, port,
            () -> McpEnvironment.headless(project, program));
        if (program != null) {
            runtime.environment().adoptBackground(program);
            runtime.environment().setPreferredProgram(program);
        }
        stopSignal = new CountDownLatch(1);
        Msg.info(GhidraMcpHeadless.class, "GhidraMCP headless server listening on "
            + host + ":" + port);
        try {
            while (!stopSignal.await(250, TimeUnit.MILLISECONDS)) {
                if (monitor != null && monitor.isCancelled()) break;
            }
        }
        finally {
            McpRuntime.release(owner);
            stopSignal = null;
        }
    }

    /** Called by shutdown_ghidra in headless mode. Returns false when not serving headless. */
    static boolean requestStop() {
        CountDownLatch latch = stopSignal;
        if (latch == null) return false;
        latch.countDown();
        return true;
    }
}
