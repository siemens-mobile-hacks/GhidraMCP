// Starts the GhidraMCP server in headless mode and blocks until the MCP tool
// shutdown_ghidra is called. Usage:
//   analyzeHeadless <projDir> <projName> [-process <file>] -noanalysis \
//       -postScript StartGhidraMcpServer.java [port] [host]
//@category GhidraMCP
import com.lauriewired.GhidraMcpHeadless;

import ghidra.app.script.GhidraScript;

public class StartGhidraMcpServer extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        String host = args.length > 1 ? args[1] : "127.0.0.1";
        println("GhidraMCP headless server on " + host + ":" + port);
        GhidraMcpHeadless.serve(state.getProject(), currentProgram, host, port, monitor);
    }
}
