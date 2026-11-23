"""Minimal MCP Streamable HTTP client (stdlib only) for end-to-end tests."""
import json
import urllib.request


class McpError(Exception):
    pass


class Mcp:
    def __init__(self, url="http://127.0.0.1:8080/mcp", timeout=600):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def rpc(self, method, params=None):
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            body["params"] = params
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
        if "error" in data:
            raise McpError(data["error"])
        return data["result"]

    def initialize(self):
        return self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "e2e", "version": "1"}})

    def tools(self):
        return {t["name"]: t for t in self.rpc("tools/list")["tools"]}

    def call(self, tool_name, /, **arguments):
        """Returns (text, is_error)."""
        r = self.rpc("tools/call", {"name": tool_name, "arguments": arguments})
        text = "\n".join(c.get("text", "") for c in r.get("content", []))
        return text, bool(r.get("isError"))
