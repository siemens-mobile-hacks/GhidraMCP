package com.lauriewired;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * Minimal Model Context Protocol server using the Streamable HTTP transport.
 *
 * <p>Every JSON-RPC request is answered with a single {@code application/json}
 * response; server-initiated SSE streams and sessions are not used, which the
 * transport explicitly permits. Only the {@code tools} capability is offered.
 */
final class McpServer implements HttpHandler {

    static final String LATEST_PROTOCOL_VERSION = "2025-11-25";
    static final List<String> SUPPORTED_PROTOCOL_VERSIONS =
        List.of("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05");

    static final int PARSE_ERROR = -32700;
    static final int INVALID_REQUEST = -32600;
    static final int METHOD_NOT_FOUND = -32601;
    static final int INVALID_PARAMS = -32602;
    static final int INTERNAL_ERROR = -32603;
    static final int RESOURCE_NOT_FOUND = -32002;

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    @FunctionalInterface
    interface ToolHandler {
        String call(Args args) throws Exception;
    }

    private final String serverName;
    private final String serverVersion;
    private final String instructions;
    private final Map<String, Tool> tools = new LinkedHashMap<>();
    private final Map<String, Prompt> prompts = new LinkedHashMap<>();
    private final List<Resource> resources = new ArrayList<>();
    private final List<ResourceTemplate> resourceTemplates = new ArrayList<>();
    private ResourceLister resourceLister;

    // ------------------------------------------------------------------
    // Prompts and resources
    // ------------------------------------------------------------------

    @FunctionalInterface
    interface PromptHandler {
        String render(Map<String, String> arguments) throws Exception;
    }

    @FunctionalInterface
    interface ResourceReader {
        String read(Map<String, String> variables) throws Exception;
    }

    /** Supplies the concrete resources for resources/list (e.g. one per open program). */
    @FunctionalInterface
    interface ResourceLister {
        List<String[]> list(); // {uri, name, description, mimeType}
    }

    private static final class Prompt {
        final String name;
        final String description;
        final List<String[]> arguments; // {name, description, required}
        final PromptHandler handler;

        Prompt(String name, String description, List<String[]> arguments, PromptHandler handler) {
            this.name = name;
            this.description = description;
            this.arguments = arguments;
            this.handler = handler;
        }
    }

    private static final class Resource {
        final String uri;
        final String name;
        final String description;
        final String mimeType;
        final ResourceReader reader;

        Resource(String uri, String name, String description, String mimeType, ResourceReader reader) {
            this.uri = uri;
            this.name = name;
            this.description = description;
            this.mimeType = mimeType;
            this.reader = reader;
        }
    }

    private static final class ResourceTemplate {
        final String uriTemplate;
        final java.util.regex.Pattern pattern;
        final List<String> variables = new ArrayList<>();
        final String name;
        final String description;
        final String mimeType;
        final ResourceReader reader;

        ResourceTemplate(String uriTemplate, String name, String description, String mimeType,
                ResourceReader reader) {
            this.uriTemplate = uriTemplate;
            this.name = name;
            this.description = description;
            this.mimeType = mimeType;
            this.reader = reader;
            StringBuilder re = new StringBuilder("^");
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\{(\\w+)\\}").matcher(uriTemplate);
            int last = 0;
            while (m.find()) {
                re.append(java.util.regex.Pattern.quote(uriTemplate.substring(last, m.start())));
                re.append("([^/]+)");
                variables.add(m.group(1));
                last = m.end();
            }
            re.append(java.util.regex.Pattern.quote(uriTemplate.substring(last))).append("$");
            this.pattern = java.util.regex.Pattern.compile(re.toString());
        }
    }

    /** Registers a prompt; arguments are {name, description, "true"/"false" required}. */
    void prompt(String name, String description, List<String[]> arguments, PromptHandler handler) {
        prompts.put(name, new Prompt(name, description, arguments, handler));
    }

    void resource(String uri, String name, String description, String mimeType, ResourceReader reader) {
        resources.add(new Resource(uri, name, description, mimeType, reader));
    }

    /** Registers a URI template like {@code ghidra://{program}/function/{function}}; variables are URL-decoded. */
    void resourceTemplate(String uriTemplate, String name, String description, String mimeType,
            ResourceReader reader) {
        resourceTemplates.add(new ResourceTemplate(uriTemplate, name, description, mimeType, reader));
    }

    void resourceLister(ResourceLister lister) {
        this.resourceLister = lister;
    }

    McpServer(String serverName, String serverVersion, String instructions) {
        this.serverName = serverName;
        this.serverVersion = serverVersion;
        this.instructions = instructions;
    }

    // ------------------------------------------------------------------
    // Tool registration
    // ------------------------------------------------------------------

    ToolBuilder tool(String name, String description) {
        return new ToolBuilder(name, description);
    }

    List<String> toolNames() {
        return new ArrayList<>(tools.keySet());
    }

    final class ToolBuilder {
        private final String name;
        private final String description;
        private final JsonObject properties = new JsonObject();
        private final JsonArray required = new JsonArray();
        private final Map<String, JsonElement> defaults = new LinkedHashMap<>();

        private ToolBuilder(String name, String description) {
            this.name = name;
            this.description = description;
        }

        /** Required string parameter. */
        ToolBuilder string(String param, String desc) {
            return add(param, schema("string", desc), null, true);
        }

        /** Optional string parameter; {@code defaultValue} may be null. */
        ToolBuilder optString(String param, String defaultValue, String desc) {
            return add(param, schema("string", desc),
                defaultValue == null ? null : new JsonPrimitive(defaultValue), false);
        }

        /** Required integer parameter. */
        ToolBuilder integer(String param, String desc) {
            return add(param, schema("integer", desc), null, true);
        }

        /** Optional integer parameter; {@code defaultValue} may be null. */
        ToolBuilder optInteger(String param, Integer defaultValue, String desc) {
            return add(param, schema("integer", desc),
                defaultValue == null ? null : new JsonPrimitive(defaultValue), false);
        }

        /** Optional boolean parameter. */
        ToolBuilder optBoolean(String param, boolean defaultValue, String desc) {
            return add(param, schema("boolean", desc), new JsonPrimitive(defaultValue), false);
        }

        /** Required array parameter whose items follow {@code itemSchema}. */
        ToolBuilder array(String param, JsonObject itemSchema, String desc) {
            JsonObject s = schema("array", desc);
            s.add("items", itemSchema);
            return add(param, s, null, true);
        }

        /** Optional array parameter whose items follow {@code itemSchema}. */
        ToolBuilder optArray(String param, JsonObject itemSchema, String desc) {
            JsonObject s = schema("array", desc);
            s.add("items", itemSchema);
            return add(param, s, null, false);
        }

        /** The common optional {@code program} selector. */
        ToolBuilder program() {
            return optString("program", "",
                "Program name or path; empty = current");
        }

        void handler(ToolHandler handler) {
            JsonObject inputSchema = new JsonObject();
            inputSchema.addProperty("type", "object");
            inputSchema.add("properties", properties);
            if (required.size() > 0) {
                inputSchema.add("required", required);
            }
            if (tools.containsKey(name)) {
                throw new IllegalStateException("Duplicate MCP tool: " + name);
            }
            tools.put(name, new Tool(name, description, inputSchema, defaults, handler));
        }

        private ToolBuilder add(String param, JsonObject s, JsonElement defaultValue, boolean isRequired) {
            if (defaultValue != null) {
                s.add("default", defaultValue);
                defaults.put(param, defaultValue);
            }
            properties.add(param, s);
            if (isRequired) {
                required.add(param);
            }
            return this;
        }
    }

    static JsonObject schema(String type, String desc) {
        JsonObject s = new JsonObject();
        s.addProperty("type", type);
        if (desc != null && !desc.isEmpty()) {
            s.addProperty("description", desc);
        }
        return s;
    }

    /** Builds an object schema from alternating (name, type) pairs; all fields optional. */
    static JsonObject objectSchema(String... nameTypePairs) {
        JsonObject props = new JsonObject();
        for (int i = 0; i + 1 < nameTypePairs.length; i += 2) {
            props.add(nameTypePairs[i], schema(nameTypePairs[i + 1], null));
        }
        JsonObject s = new JsonObject();
        s.addProperty("type", "object");
        s.add("properties", props);
        return s;
    }

    private static final class Tool {
        final String name;
        final String description;
        final JsonObject inputSchema;
        final Map<String, JsonElement> defaults;
        final ToolHandler handler;
        final Set<String> arrayParams;

        Tool(String name, String description, JsonObject inputSchema,
                Map<String, JsonElement> defaults, ToolHandler handler) {
            this.name = name;
            this.description = description;
            this.inputSchema = inputSchema;
            this.defaults = defaults;
            this.handler = handler;
            this.arrayParams = findArrayParams(inputSchema);
        }

        private static Set<String> findArrayParams(JsonObject inputSchema) {
            Set<String> names = new HashSet<>();
            for (Map.Entry<String, JsonElement> e : inputSchema.getAsJsonObject("properties").entrySet()) {
                JsonElement type = e.getValue().getAsJsonObject().get("type");
                if (type != null && "array".equals(type.getAsString())) names.add(e.getKey());
            }
            return names;
        }

        JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.addProperty("description", description);
            o.add("inputSchema", inputSchema);
            return o;
        }
    }

    /** Thrown by argument accessors when a value is missing or has the wrong type. */
    static final class InvalidArgumentException extends RuntimeException {
        InvalidArgumentException(String message) {
            super(message);
        }
    }

    /** Tool-call arguments with schema defaults applied. */
    static final class Args {
        private final JsonObject values;
        private final Map<String, JsonElement> defaults;
        private final Set<String> arrayParams;

        Args(JsonObject values, Map<String, JsonElement> defaults, Set<String> arrayParams) {
            this.values = values;
            this.defaults = defaults;
            this.arrayParams = arrayParams;
        }

        private JsonElement raw(String name) {
            JsonElement v = values.get(name);
            if (v == null || v.isJsonNull()) {
                v = defaults.get(name);
            }
            return v == null || v.isJsonNull() ? null : v;
        }

        boolean has(String name) {
            return raw(name) != null;
        }

        /** String value, default, or null. Scalars of other types are stringified. */
        String str(String name) {
            JsonElement v = raw(name);
            if (v == null) return null;
            if (!v.isJsonPrimitive()) {
                throw new InvalidArgumentException("Argument '" + name + "' must be a string");
            }
            return v.getAsString();
        }

        /** Integer value or default; throws when absent and no default exists. */
        int integer(String name) {
            Integer v = optInteger(name);
            if (v == null) {
                throw new InvalidArgumentException("Missing required argument '" + name + "'");
            }
            return v;
        }

        Integer optInteger(String name) {
            JsonElement v = raw(name);
            if (v == null) return null;
            try {
                if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isNumber()) {
                    double d = v.getAsDouble();
                    if (d != Math.rint(d) || d > Integer.MAX_VALUE || d < Integer.MIN_VALUE) {
                        throw new NumberFormatException();
                    }
                    return (int) d;
                }
                if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
                    return Integer.parseInt(v.getAsString().trim());
                }
            }
            catch (NumberFormatException e) {
                // fall through
            }
            throw new InvalidArgumentException("Argument '" + name + "' must be an integer");
        }

        boolean bool(String name) {
            JsonElement v = raw(name);
            if (v == null) return false;
            if (v.isJsonPrimitive()) {
                JsonPrimitive p = v.getAsJsonPrimitive();
                if (p.isBoolean()) return p.getAsBoolean();
                if (p.isString()) {
                    String s = p.getAsString().trim();
                    if (s.equalsIgnoreCase("true") || s.equals("1")) return true;
                    if (s.equalsIgnoreCase("false") || s.equals("0") || s.isEmpty()) return false;
                }
                if (p.isNumber()) return p.getAsDouble() != 0;
            }
            throw new InvalidArgumentException("Argument '" + name + "' must be a boolean");
        }

        /** Array value, or an empty array when absent. */
        JsonArray array(String name) {
            JsonElement v = raw(name);
            if (v == null) return new JsonArray();
            if (v.isJsonArray()) return v.getAsJsonArray();
            // Some clients send structured arguments JSON-encoded as a string.
            if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
                try {
                    JsonElement parsed = JsonParser.parseString(v.getAsString());
                    if (parsed.isJsonArray()) return parsed.getAsJsonArray();
                }
                catch (JsonParseException e) {
                    // fall through
                }
            }
            throw new InvalidArgumentException("Argument '" + name + "' must be an array");
        }

        /**
         * JSON object containing the given keys with their values or defaults;
         * keys that have neither are omitted. Array parameters are normalized.
         */
        JsonObject object(String... keys) {
            JsonObject o = new JsonObject();
            for (String key : keys) {
                JsonElement v = raw(key);
                if (v == null) continue;
                o.add(key, arrayParams.contains(key) ? array(key) : v);
            }
            return o;
        }
    }

    // ------------------------------------------------------------------
    // JSON-RPC dispatch (transport independent, used directly by tests)
    // ------------------------------------------------------------------

    /**
     * Handles one JSON-RPC payload (a message or a batch) and returns the
     * serialized response, or null when nothing needs to be returned.
     */
    String handlePayload(String body) {
        JsonElement payload;
        try {
            payload = JsonParser.parseString(body);
        }
        catch (JsonParseException e) {
            return GSON.toJson(error(null, PARSE_ERROR, "Parse error: " + e.getMessage()));
        }

        if (payload.isJsonArray()) {
            JsonArray responses = new JsonArray();
            for (JsonElement message : payload.getAsJsonArray()) {
                JsonObject response = handleMessage(message);
                if (response != null) responses.add(response);
            }
            if (payload.getAsJsonArray().size() == 0) {
                return GSON.toJson(error(null, INVALID_REQUEST, "Empty batch"));
            }
            return responses.size() == 0 ? null : GSON.toJson(responses);
        }
        JsonObject response = handleMessage(payload);
        return response == null ? null : GSON.toJson(response);
    }

    private JsonObject handleMessage(JsonElement element) {
        if (!element.isJsonObject()) {
            return error(null, INVALID_REQUEST, "Invalid request");
        }
        JsonObject message = element.getAsJsonObject();
        JsonElement id = message.get("id");
        boolean isNotification = id == null;
        JsonElement methodElement = message.get("method");

        if (methodElement == null) {
            // A response to a server-initiated request; we never send any.
            return null;
        }
        if (!methodElement.isJsonPrimitive()) {
            return isNotification ? null : error(id, INVALID_REQUEST, "Invalid method");
        }
        String method = methodElement.getAsString();
        JsonObject params = message.has("params") && message.get("params").isJsonObject()
            ? message.getAsJsonObject("params") : new JsonObject();

        if (isNotification) {
            return null; // notifications/initialized, notifications/cancelled, ...
        }

        try {
            switch (method) {
                case "initialize":
                    return result(id, initialize(params));
                case "ping":
                    return result(id, new JsonObject());
                case "tools/list":
                    return result(id, listTools());
                case "tools/call":
                    return callTool(id, params);
                case "prompts/list":
                    return result(id, listPrompts());
                case "prompts/get":
                    return getPrompt(id, params);
                case "resources/list":
                    return result(id, listResources());
                case "resources/templates/list":
                    return result(id, listResourceTemplates());
                case "resources/read":
                    return readResource(id, params);
                default:
                    return error(id, METHOD_NOT_FOUND, "Method not found: " + method);
            }
        }
        catch (Exception e) {
            return error(id, INTERNAL_ERROR, "Internal error: " + e);
        }
    }

    private JsonObject initialize(JsonObject params) {
        String requested = params.has("protocolVersion") && params.get("protocolVersion").isJsonPrimitive()
            ? params.get("protocolVersion").getAsString() : null;
        String version = requested != null && SUPPORTED_PROTOCOL_VERSIONS.contains(requested)
            ? requested : LATEST_PROTOCOL_VERSION;

        JsonObject toolsCapability = new JsonObject();
        toolsCapability.addProperty("listChanged", false);
        JsonObject capabilities = new JsonObject();
        capabilities.add("tools", toolsCapability);
        if (!prompts.isEmpty()) {
            JsonObject pc = new JsonObject();
            pc.addProperty("listChanged", false);
            capabilities.add("prompts", pc);
        }
        if (!resources.isEmpty() || !resourceTemplates.isEmpty() || resourceLister != null) {
            JsonObject rc = new JsonObject();
            rc.addProperty("listChanged", false);
            rc.addProperty("subscribe", false);
            capabilities.add("resources", rc);
        }

        JsonObject info = new JsonObject();
        info.addProperty("name", serverName);
        info.addProperty("version", serverVersion);

        JsonObject r = new JsonObject();
        r.addProperty("protocolVersion", version);
        r.add("capabilities", capabilities);
        r.add("serverInfo", info);
        if (instructions != null && !instructions.isEmpty()) {
            r.addProperty("instructions", instructions);
        }
        return r;
    }

    private JsonObject listTools() {
        JsonArray list = new JsonArray();
        for (Tool t : tools.values()) {
            list.add(t.toJson());
        }
        JsonObject r = new JsonObject();
        r.add("tools", list);
        return r;
    }

    private JsonObject callTool(JsonElement id, JsonObject params) {
        String name = params.has("name") && params.get("name").isJsonPrimitive()
            ? params.get("name").getAsString() : null;
        Tool tool = name == null ? null : tools.get(name);
        if (tool == null) {
            return error(id, INVALID_PARAMS, "Unknown tool: " + name);
        }
        JsonObject arguments = params.has("arguments") && params.get("arguments").isJsonObject()
            ? params.getAsJsonObject("arguments") : new JsonObject();

        for (JsonElement req : tool.inputSchema.has("required")
                ? tool.inputSchema.getAsJsonArray("required") : new JsonArray()) {
            JsonElement v = arguments.get(req.getAsString());
            if (v == null || v.isJsonNull()) {
                return result(id, toolResult("Missing required argument '" + req.getAsString() + "'", true));
            }
        }

        try {
            String text = tool.handler.call(new Args(arguments, tool.defaults, tool.arrayParams));
            return result(id, toolResult(text == null ? "" : text, false));
        }
        catch (InvalidArgumentException e) {
            return result(id, toolResult(e.getMessage(), true));
        }
        catch (Exception e) {
            return result(id, toolResult("Tool '" + name + "' failed: " + e, true));
        }
    }

    private JsonObject listPrompts() {
        JsonArray list = new JsonArray();
        for (Prompt p : prompts.values()) {
            JsonObject o = new JsonObject();
            o.addProperty("name", p.name);
            o.addProperty("description", p.description);
            JsonArray args = new JsonArray();
            for (String[] a : p.arguments) {
                JsonObject ao = new JsonObject();
                ao.addProperty("name", a[0]);
                ao.addProperty("description", a[1]);
                ao.addProperty("required", Boolean.parseBoolean(a[2]));
                args.add(ao);
            }
            o.add("arguments", args);
            list.add(o);
        }
        JsonObject r = new JsonObject();
        r.add("prompts", list);
        return r;
    }

    private JsonObject getPrompt(JsonElement id, JsonObject params) {
        String name = params.has("name") ? params.get("name").getAsString() : null;
        Prompt p = name == null ? null : prompts.get(name);
        if (p == null) return error(id, INVALID_PARAMS, "Unknown prompt: " + name);
        Map<String, String> args = new LinkedHashMap<>();
        if (params.has("arguments") && params.get("arguments").isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : params.getAsJsonObject("arguments").entrySet()) {
                if (!e.getValue().isJsonNull()) args.put(e.getKey(), e.getValue().getAsString());
            }
        }
        for (String[] a : p.arguments) {
            if (Boolean.parseBoolean(a[2]) && (args.get(a[0]) == null || args.get(a[0]).isBlank())) {
                return error(id, INVALID_PARAMS, "Missing required prompt argument '" + a[0] + "'");
            }
        }
        String text;
        try {
            text = p.handler.render(args);
        }
        catch (InvalidArgumentException e) {
            return error(id, INVALID_PARAMS, e.getMessage());
        }
        catch (Exception e) {
            return error(id, INTERNAL_ERROR, "Prompt '" + name + "' failed: " + e);
        }
        JsonObject content = new JsonObject();
        content.addProperty("type", "text");
        content.addProperty("text", text);
        JsonObject message = new JsonObject();
        message.addProperty("role", "user");
        message.add("content", content);
        JsonArray messages = new JsonArray();
        messages.add(message);
        JsonObject r = new JsonObject();
        r.addProperty("description", p.description);
        r.add("messages", messages);
        return result(id, r);
    }

    private JsonObject listResources() {
        JsonArray list = new JsonArray();
        for (Resource res : resources) {
            list.add(resourceJson(res.uri, res.name, res.description, res.mimeType));
        }
        if (resourceLister != null) {
            for (String[] r : resourceLister.list()) {
                list.add(resourceJson(r[0], r[1], r[2], r[3]));
            }
        }
        JsonObject r = new JsonObject();
        r.add("resources", list);
        return r;
    }

    private static JsonObject resourceJson(String uri, String name, String description, String mimeType) {
        JsonObject o = new JsonObject();
        o.addProperty("uri", uri);
        o.addProperty("name", name);
        if (description != null) o.addProperty("description", description);
        if (mimeType != null) o.addProperty("mimeType", mimeType);
        return o;
    }

    private JsonObject listResourceTemplates() {
        JsonArray list = new JsonArray();
        for (ResourceTemplate t : resourceTemplates) {
            JsonObject o = new JsonObject();
            o.addProperty("uriTemplate", t.uriTemplate);
            o.addProperty("name", t.name);
            o.addProperty("description", t.description);
            o.addProperty("mimeType", t.mimeType);
            list.add(o);
        }
        JsonObject r = new JsonObject();
        r.add("resourceTemplates", list);
        return r;
    }

    private JsonObject readResource(JsonElement id, JsonObject params) {
        String uri = params.has("uri") ? params.get("uri").getAsString() : null;
        if (uri == null) return error(id, INVALID_PARAMS, "Missing uri");
        ResourceReader reader = null;
        String mime = "text/plain";
        Map<String, String> vars = new LinkedHashMap<>();
        for (Resource res : resources) {
            if (res.uri.equals(uri)) {
                reader = res.reader;
                mime = res.mimeType;
            }
        }
        if (reader == null) {
            for (ResourceTemplate t : resourceTemplates) {
                java.util.regex.Matcher m = t.pattern.matcher(uri);
                if (!m.matches()) continue;
                for (int i = 0; i < t.variables.size(); i++) {
                    vars.put(t.variables.get(i),
                        // RFC 3986 percent-decoding: a literal '+' stays '+'
                        java.net.URLDecoder.decode(m.group(i + 1).replace("+", "%2B"),
                            java.nio.charset.StandardCharsets.UTF_8));
                }
                reader = t.reader;
                mime = t.mimeType;
                break;
            }
        }
        if (reader == null) return error(id, RESOURCE_NOT_FOUND, "Resource not found: " + uri);
        String text;
        try {
            text = reader.read(vars);
        }
        catch (InvalidArgumentException e) {
            return error(id, RESOURCE_NOT_FOUND, e.getMessage());
        }
        catch (Exception e) {
            return error(id, INTERNAL_ERROR, "Reading " + uri + " failed: " + e);
        }
        JsonObject content = new JsonObject();
        content.addProperty("uri", uri);
        content.addProperty("mimeType", mime);
        content.addProperty("text", text);
        JsonArray contents = new JsonArray();
        contents.add(content);
        JsonObject r = new JsonObject();
        r.add("contents", contents);
        return result(id, r);
    }

    private static JsonObject toolResult(String text, boolean isError) {
        JsonObject content = new JsonObject();
        content.addProperty("type", "text");
        content.addProperty("text", text);
        JsonArray contents = new JsonArray();
        contents.add(content);
        JsonObject r = new JsonObject();
        r.add("content", contents);
        r.addProperty("isError", isError);
        return r;
    }

    private static JsonObject result(JsonElement id, JsonObject result) {
        JsonObject r = new JsonObject();
        r.addProperty("jsonrpc", "2.0");
        r.add("id", id);
        r.add("result", result);
        return r;
    }

    private static JsonObject error(JsonElement id, int code, String message) {
        JsonObject err = new JsonObject();
        err.addProperty("code", code);
        err.addProperty("message", message);
        JsonObject r = new JsonObject();
        r.addProperty("jsonrpc", "2.0");
        r.add("id", id);
        r.add("error", err);
        return r;
    }

    // ------------------------------------------------------------------
    // HTTP transport
    // ------------------------------------------------------------------

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod();
            if (!"POST".equalsIgnoreCase(method)) {
                // No server-initiated SSE stream and no sessions to delete.
                exchange.getResponseHeaders().set("Allow", "POST");
                send(exchange, 405, null, null);
                return;
            }
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String response = handlePayload(body);
            if (response == null) {
                send(exchange, 202, null, null);
            }
            else {
                send(exchange, 200, "application/json; charset=utf-8", response);
            }
        }
        finally {
            exchange.close();
        }
    }

    private static void send(HttpExchange exchange, int status, String contentType, String body)
            throws IOException {
        if (body == null) {
            exchange.sendResponseHeaders(status, -1);
            return;
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * True when the request carries no Origin header (non-browser clients) or
     * an Origin on a loopback host. Rejecting other origins prevents web pages
     * from driving the local server via DNS rebinding or cross-site requests.
     */
    static boolean isAllowedOrigin(String origin) {
        if (origin == null || origin.isEmpty()) return true;
        try {
            String host = new URI(origin.trim()).getHost();
            if (host == null) return false;
            host = host.toLowerCase();
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            return host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1");
        }
        catch (Exception e) {
            return false;
        }
    }

    /** HTTP filter that answers 403 for requests from non-loopback origins. */
    static Filter originFilter() {
        return new Filter() {
            @Override
            public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                if (isAllowedOrigin(exchange.getRequestHeaders().getFirst("Origin"))) {
                    chain.doFilter(exchange);
                    return;
                }
                byte[] bytes = "Forbidden origin".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
                exchange.sendResponseHeaders(403, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
                exchange.close();
            }

            @Override
            public String description() {
                return "Rejects requests from non-loopback browser origins";
            }
        };
    }
}
