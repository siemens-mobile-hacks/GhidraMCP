package com.lauriewired;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * Process-wide owner of the embedded HTTP/MCP server.
 *
 * <p>The project-window plugin, every CodeBrowser plugin instance and the
 * headless start script acquire the runtime; the server is started by the
 * first owner and stopped when the last one releases it. Because programs are
 * resolved globally by {@link McpEnvironment}, it does not matter which owner
 * started the server.
 */
final class McpRuntime {

    static final String VERSION = "2.0.0";

    private static McpRuntime instance;
    private static final Set<Object> owners = new LinkedHashSet<>();

    private final String host;
    private final int port;
    private final McpEnvironment environment;
    private final GhidraMcpCore core;
    private final HttpServer server;
    private final ExecutorService executor;
    private final long startedAt = System.currentTimeMillis();

    private McpRuntime(String host, int port, McpEnvironment environment) throws IOException {
        this.host = host;
        this.port = port;
        this.environment = environment;
        this.core = new GhidraMcpCore(environment, this);
        this.server = HttpServer.create(new InetSocketAddress(host, port), 0);
        AtomicInteger threadIds = new AtomicInteger();
        this.executor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "GhidraMCP-HTTP-" + threadIds.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        core.registerEndpoints(server);
        server.setExecutor(executor);
        server.start();
        Msg.info(McpRuntime.class, "GhidraMCP server started on " + host + ":" + port
            + (environment.isHeadless() ? " (headless)" : ""));
    }

    /**
     * Registers {@code owner} and starts the server if it is not running yet.
     * The host/port of the first owner win; later owners share the server.
     */
    static synchronized McpRuntime acquire(Object owner, String host, int port,
            Supplier<McpEnvironment> environmentFactory) throws IOException {
        if (instance == null) {
            instance = new McpRuntime(host, port, environmentFactory.get());
        }
        else if (instance.port != port || !instance.host.equals(host)) {
            Msg.info(McpRuntime.class, "GhidraMCP server already running on " + instance.host + ":"
                + instance.port + "; ignoring " + host + ":" + port + " requested by "
                + owner.getClass().getSimpleName());
        }
        owners.add(owner);
        return instance;
    }

    /** Unregisters {@code owner}; stops the server when no owners remain. */
    static synchronized void release(Object owner) {
        owners.remove(owner);
        if (owners.isEmpty() && instance != null) {
            instance.stop();
            instance = null;
        }
    }

    static synchronized McpRuntime current() {
        return instance;
    }

    static synchronized int ownerCount() {
        return owners.size();
    }

    static synchronized String ownerSummary() {
        StringBuilder sb = new StringBuilder();
        for (Object o : owners) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(o.getClass().getSimpleName());
        }
        return sb.toString();
    }

    private void stop() {
        Msg.info(McpRuntime.class, "Stopping GhidraMCP server on " + host + ":" + port);
        server.stop(1);
        executor.shutdownNow();
        core.dispose();
        environment.releaseAll();
    }

    String host() {
        return host;
    }

    int port() {
        return port;
    }

    long startedAt() {
        return startedAt;
    }

    McpEnvironment environment() {
        return environment;
    }

    GhidraMcpCore core() {
        return core;
    }
}
