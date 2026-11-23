package com.lauriewired;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import junit.framework.TestCase;

public class McpServerTest extends TestCase {

    private McpServer server;

    @Override
    protected void setUp() {
        server = new McpServer("test", "0.1", "hello");
        server.tool("echo", "Echo arguments")
            .string("text", "Text")
            .optInteger("count", 2, "Repeats")
            .optBoolean("upper", false, "Upper-case")
            .optArray("tags", McpServer.schema("string", null), "Tags")
            .optString("program", "", "Program")
            .handler(a -> {
                String t = a.bool("upper") ? a.str("text").toUpperCase() : a.str("text");
                return t.repeat(a.integer("count")) + "|" + a.str("program") + "|"
                    + a.object("text", "tags", "missing");
            });
        server.tool("boom", "Fails").handler(a -> {
            throw new IllegalStateException("kaput");
        });
    }

    private JsonObject call(String json) {
        String response = server.handlePayload(json);
        assertNotNull(response);
        return JsonParser.parseString(response).getAsJsonObject();
    }

    public void testInitializeEchoesSupportedVersion() {
        JsonObject r = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":"
            + "{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
            + "\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}");
        JsonObject result = r.getAsJsonObject("result");
        assertEquals(1, r.get("id").getAsInt());
        assertEquals("2025-06-18", result.get("protocolVersion").getAsString());
        assertTrue(result.getAsJsonObject("capabilities").has("tools"));
        assertEquals("test", result.getAsJsonObject("serverInfo").get("name").getAsString());
        assertEquals("hello", result.get("instructions").getAsString());
    }

    public void testInitializeFallsBackToLatestVersion() {
        JsonObject r = call("{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"initialize\","
            + "\"params\":{\"protocolVersion\":\"1999-01-01\"}}");
        assertEquals("a", r.get("id").getAsString());
        assertEquals(McpServer.LATEST_PROTOCOL_VERSION,
            r.getAsJsonObject("result").get("protocolVersion").getAsString());
    }

    public void testNotificationsProduceNoResponse() {
        assertNull(server.handlePayload("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"));
        assertNull(server.handlePayload("[{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}]"));
    }

    public void testToolsListContainsSchemas() {
        JsonObject r = call("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");
        JsonArray tools = r.getAsJsonObject("result").getAsJsonArray("tools");
        assertEquals(2, tools.size());
        JsonObject echo = tools.get(0).getAsJsonObject();
        assertEquals("echo", echo.get("name").getAsString());
        JsonObject schema = echo.getAsJsonObject("inputSchema");
        assertEquals("object", schema.get("type").getAsString());
        assertEquals("text", schema.getAsJsonArray("required").get(0).getAsString());
        assertEquals(1, schema.getAsJsonArray("required").size());
        JsonObject props = schema.getAsJsonObject("properties");
        assertEquals("integer", props.getAsJsonObject("count").get("type").getAsString());
        assertEquals(2, props.getAsJsonObject("count").get("default").getAsInt());
        assertEquals("string", props.getAsJsonObject("tags").getAsJsonObject("items")
            .get("type").getAsString());
    }

    public void testToolCallAppliesDefaultsAndCoercion() {
        JsonObject r = call("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":"
            + "{\"name\":\"echo\",\"arguments\":{\"text\":\"ab\",\"upper\":\"true\","
            + "\"tags\":\"[\\\"x\\\"]\"}}}");
        JsonObject result = r.getAsJsonObject("result");
        assertFalse(result.get("isError").getAsBoolean());
        assertEquals("ABAB||{\"text\":\"ab\",\"tags\":[\"x\"]}", text(result));

        r = call("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":"
            + "{\"name\":\"echo\",\"arguments\":{\"text\":\"z\",\"count\":\"3\",\"program\":\"p\"}}}");
        assertEquals("zzz|p|{\"text\":\"z\"}", text(r.getAsJsonObject("result")));
    }

    public void testToolCallErrors() {
        JsonObject missing = call("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"echo\",\"arguments\":{}}}");
        assertTrue(missing.getAsJsonObject("result").get("isError").getAsBoolean());
        assertTrue(text(missing.getAsJsonObject("result")).contains("'text'"));

        JsonObject badType = call("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"a\",\"count\":1.5}}}");
        assertTrue(badType.getAsJsonObject("result").get("isError").getAsBoolean());

        JsonObject boom = call("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"boom\"}}");
        assertTrue(boom.getAsJsonObject("result").get("isError").getAsBoolean());
        assertTrue(text(boom.getAsJsonObject("result")).contains("kaput"));

        JsonObject unknown = call("{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"nope\"}}");
        assertEquals(McpServer.INVALID_PARAMS, unknown.getAsJsonObject("error").get("code").getAsInt());
    }

    public void testProtocolErrors() {
        assertEquals(McpServer.PARSE_ERROR,
            call("{oops").getAsJsonObject("error").get("code").getAsInt());
        assertEquals(McpServer.METHOD_NOT_FOUND,
            call("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"completion/complete\"}")
                .getAsJsonObject("error").get("code").getAsInt());
        JsonObject ping = call("{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"ping\"}");
        assertEquals(0, ping.getAsJsonObject("result").size());
    }

    public void testOriginValidation() {
        assertTrue(McpServer.isAllowedOrigin(null));
        assertTrue(McpServer.isAllowedOrigin(""));
        assertTrue(McpServer.isAllowedOrigin("http://localhost:3000"));
        assertTrue(McpServer.isAllowedOrigin("http://127.0.0.1"));
        assertTrue(McpServer.isAllowedOrigin("http://[::1]:8080"));
        assertFalse(McpServer.isAllowedOrigin("https://evil.example"));
        assertFalse(McpServer.isAllowedOrigin("http://localhost.evil.example"));
        assertFalse(McpServer.isAllowedOrigin("null"));
    }

    public void testPromptsAndResources() {
        java.util.List<String[]> args = new java.util.ArrayList<>();
        args.add(new String[] { "name", "Name", "true" });
        server.prompt("greet", "Greets", args, a -> "Hello " + a.get("name"));
        server.resourceTemplate("ghidra://{program}/function/{function}/decompile", "Decompiled", "d",
            "text/x-c", v -> v.get("program") + "|" + v.get("function"));
        server.resource("ghidra://static", "Static", "s", "text/plain", v -> "static text");

        JsonObject init = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}");
        JsonObject caps = init.getAsJsonObject("result").getAsJsonObject("capabilities");
        assertTrue(caps.has("prompts"));
        assertTrue(caps.has("resources"));

        JsonObject list = call("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"prompts/list\"}");
        JsonObject prompt = list.getAsJsonObject("result").getAsJsonArray("prompts").get(0).getAsJsonObject();
        assertEquals("greet", prompt.get("name").getAsString());
        assertTrue(prompt.getAsJsonArray("arguments").get(0).getAsJsonObject().get("required").getAsBoolean());

        JsonObject got = call("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"prompts/get\",\"params\":"
            + "{\"name\":\"greet\",\"arguments\":{\"name\":\"Bob\"}}}");
        JsonObject msg = got.getAsJsonObject("result").getAsJsonArray("messages").get(0).getAsJsonObject();
        assertEquals("user", msg.get("role").getAsString());
        assertEquals("Hello Bob", msg.getAsJsonObject("content").get("text").getAsString());

        JsonObject missing = call("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"prompts/get\",\"params\":"
            + "{\"name\":\"greet\"}}");
        assertEquals(McpServer.INVALID_PARAMS, missing.getAsJsonObject("error").get("code").getAsInt());

        JsonObject read = call("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"resources/read\",\"params\":"
            + "{\"uri\":\"ghidra://%2Fdir%2Fprog/function/A%3A%3Af/decompile\"}}");
        JsonObject content = read.getAsJsonObject("result").getAsJsonArray("contents").get(0).getAsJsonObject();
        assertEquals("/dir/prog|A::f", content.get("text").getAsString());
        assertEquals("text/x-c", content.get("mimeType").getAsString());

        JsonObject stat = call("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\",\"params\":"
            + "{\"uri\":\"ghidra://static\"}}");
        assertEquals("static text", stat.getAsJsonObject("result").getAsJsonArray("contents").get(0)
            .getAsJsonObject().get("text").getAsString());

        JsonObject none = call("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"resources/read\",\"params\":"
            + "{\"uri\":\"ghidra://nope/x\"}}");
        assertEquals(McpServer.RESOURCE_NOT_FOUND, none.getAsJsonObject("error").get("code").getAsInt());

        JsonObject templates = call("{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"resources/templates/list\"}");
        assertEquals(1, templates.getAsJsonObject("result").getAsJsonArray("resourceTemplates").size());
        JsonObject resources = call("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"resources/list\"}");
        assertEquals(1, resources.getAsJsonObject("result").getAsJsonArray("resources").size());
    }

    public void testPagingDoesNotOverflow() {
        java.util.List<String> items = java.util.Arrays.asList("a", "b", "c");
        assertEquals("b\nc\n-- 2-3 of 3 --", McpSupport.page(items, 1, Integer.MAX_VALUE));
        assertEquals("a\n-- 1-1 of 3; next offset 1 --", McpSupport.page(items, 0, 1));
    }

    public void testResourcePlusIsLiteral() {
        server.resourceTemplate("ghidra://{program}/function/{function}/decompile", "D", "d", "text/x-c",
            v -> v.get("function"));
        JsonObject read = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":"
            + "{\"uri\":\"ghidra://p/function/operator+/decompile\"}}");
        assertEquals("operator+", read.getAsJsonObject("result").getAsJsonArray("contents").get(0)
            .getAsJsonObject().get("text").getAsString());
    }

    private static String text(JsonObject result) {
        return result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString();
    }
}
