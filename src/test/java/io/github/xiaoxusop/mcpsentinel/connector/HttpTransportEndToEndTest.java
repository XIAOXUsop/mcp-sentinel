package io.github.xiaoxusop.mcpsentinel.connector;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Streamable HTTP 连接：本地受控服务器，不访问公网。
 *
 * <p>要守住的性质有五条，每一条都对应一种"看起来连上了、其实什么都没拉回来"的失败：
 * <ul>
 *   <li>正常路径真的拉到了工具面（而不是空列表）；</li>
 *   <li>连不上时给可读诊断而不是堆栈；</li>
 *   <li>HTTP 错误码不被当成"服务器没有工具"；</li>
 *   <li>非法 JSON-RPC 不被静默吞掉；</li>
 *   <li>请求头里的密钥来自环境变量，缺失时**连之前就失败**。</li>
 * </ul>
 */
class HttpTransportEndToEndTest {

    private static final String TOOLS_RESULT = """
            {"jsonrpc":"2.0","id":%s,"result":{"tools":[
              {"name":"lookup","description":"Looks up a record.",
               "inputSchema":{"type":"object","properties":{"id":{"type":"string","pattern":"^[0-9]+$"}},
                              "required":["id"]}}]}}""";

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    /** 起一个最小的 MCP Streamable HTTP 服务器；{@code responder} 决定每次请求的响应 */
    private String startServer(Responder responder) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/mcp", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            AtomicReference<String> authorization = new AtomicReference<>();
            if (exchange.getRequestHeaders().getFirst("Authorization") != null) {
                authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            }
            responder.respond(exchange, body, authorization.get());
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/mcp";
    }

    private interface Responder {
        void respond(HttpExchange exchange, String body, String authorization) throws IOException;
    }

    private static void send(HttpExchange exchange, int status, String json) throws IOException {
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(payload);
        }
    }

    /** 应答 initialize 与 tools/list，其余（notification）回 202 */
    private static void normalMcpFlow(HttpExchange exchange, String body) throws IOException {
        if (body.contains("\"initialize\"")) {
            send(exchange, 200, """
                    {"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18",
                     "capabilities":{"tools":{}},"serverInfo":{"name":"http-test-server","version":"1.0.0"}}}"""
                    .formatted(idOf(body)));
            return;
        }
        if (body.contains("\"tools/list\"")) {
            send(exchange, 200, TOOLS_RESULT.formatted(idOf(body)));
            return;
        }
        exchange.sendResponseHeaders(202, -1);
        exchange.close();
    }

    /**
     * 把请求里的 JSON-RPC id **原样**取回来。
     *
     * <p>必须原样：SDK 发的 id 是字符串（`"2a1da50f-0"`），回一个数字 id 就配不上对，
     * 客户端会直接报 "failed to initialize"。这条是实测踩出来的——
     * 一开始按"id 一定是数字"写，结果正常路径一直失败。
     */
    private static String idOf(String body) {
        int at = body.indexOf("\"id\":");
        if (at < 0) {
            return "1";
        }
        int start = at + 5;
        while (start < body.length() && Character.isWhitespace(body.charAt(start))) {
            start++;
        }
        int end = start;
        if (start < body.length() && body.charAt(start) == '"') {
            end = body.indexOf('"', start + 1) + 1;
        } else {
            while (end < body.length() && body.charAt(end) != ',' && body.charAt(end) != '}') {
                end++;
            }
        }
        return body.substring(start, Math.max(end, start + 1)).trim();
    }

    private static ServerTarget httpTarget(String url) {
        return new ServerTarget("http-test-server", ServerTarget.Transport.STREAMABLE_HTTP,
                "", java.util.List.of(), java.util.Map.of(), url, java.util.Map.of(), Duration.ofSeconds(10));
    }

    // ---------- 正常路径 ----------

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void pullsTheToolSurfaceOverStreamableHttp() throws Exception {
        String url = startServer((exchange, body, authorization) -> normalMcpFlow(exchange, body))
                .toString();

        McpConnector.Result result = McpConnector.connect(httpTarget(url));

        assertTrue(result.ok(), "应连上并拉到工具面，实际：" + result.error());
        ToolSurface surface = result.surface();
        assertEquals("http-test-server", surface.serverName());
        assertEquals(1, surface.tools().size());
        assertEquals("lookup", surface.tools().get(0).name());
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void sendsHeadersReferencedFromEnvironmentVariables(@TempDir Path dir) throws Exception {
        AtomicReference<String> seen = new AtomicReference<>();
        String url = startServer((exchange, body, authorization) -> {
            seen.set(authorization);
            normalMcpFlow(exchange, body);
        });

        Path config = dir.resolve("mcp.json");
        Files.writeString(config, """
                {"server":"http-test-server","transport":"streamable-http","url":"%s",
                 "headers":{"Authorization":"Bearer ${MCP_SENTINEL_TEST_TOKEN}"}}""".formatted(url));
        ServerTarget target = ServerTarget.read(config);

        java.util.Map<String, String> headers = target.resolveHeaders(name -> "secret-value");

        assertEquals(java.util.Map.of("Authorization", "Bearer secret-value"), headers);
        // 配置里不出现明文
        assertFalse(Files.readString(config).contains("secret-value"));
    }

    @Test
    void missingEnvironmentVariableFailsBeforeConnecting(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json");
        Files.writeString(config, """
                {"server":"s","transport":"streamable-http","url":"http://127.0.0.1:1/mcp",
                 "headers":{"Authorization":"Bearer ${DEFINITELY_NOT_SET_VAR}"}}""");
        ServerTarget target = ServerTarget.read(config);

        IOException failure = org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                () -> target.resolveHeaders(name -> null));

        assertTrue(failure.getMessage().contains("DEFINITELY_NOT_SET_VAR"), failure.getMessage());
        assertTrue(failure.getMessage().contains("环境变量"), failure.getMessage());
    }

    // ---------- 失败路径 ----------

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void unreachableEndpointFailsWithAReadableDiagnosis() {
        // 端口上什么都没有：拿一个刚关掉的端口
        McpConnector.Result result = McpConnector.connect(
                httpTarget("http://127.0.0.1:1/mcp"));

        assertFalse(result.ok());
        assertTrue(result.error() != null && !result.error().isBlank(), "失败要有可读原因");
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void httpErrorIsNotMistakenForAnEmptySurface() throws Exception {
        String url = startServer((exchange, body, authorization) -> send(exchange, 500, "{\"error\":\"boom\"}"));

        McpConnector.Result result = McpConnector.connect(httpTarget(url));

        assertFalse(result.ok(), "500 不该被当成'该服务器没有工具'");
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void malformedJsonRpcIsRejectedRatherThanSilentlyIgnored() throws Exception {
        String url = startServer((exchange, body, authorization) -> send(exchange, 200, "{ this is not json"));

        McpConnector.Result result = McpConnector.connect(httpTarget(url));

        assertFalse(result.ok());
        assertFalse(result.error().isEmpty());
    }

    // ---------- 配置解析 ----------

    @Test
    void transportIsParsedAndDefaultsToStdio() throws Exception {
        assertEquals(ServerTarget.Transport.STDIO, ServerTarget.Transport.parse(""));
        assertEquals(ServerTarget.Transport.STDIO, ServerTarget.Transport.parse("stdio"));
        assertEquals(ServerTarget.Transport.STREAMABLE_HTTP, ServerTarget.Transport.parse("streamable-http"));
        assertEquals(ServerTarget.Transport.STREAMABLE_HTTP, ServerTarget.Transport.parse("HTTP"));
        assertTrue(org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                () -> ServerTarget.Transport.parse("carrier-pigeon")).getMessage().contains("streamable-http"));
    }

    @Test
    void stdioConfigStillParsesExactlyAsBefore(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json");
        Files.writeString(config, """
                {"server":"my-server","command":"java","args":["-jar","server.jar"],
                 "env":{"API_KEY":"x"},"timeoutSeconds":30}""");

        ServerTarget target = ServerTarget.read(config);

        assertEquals(ServerTarget.Transport.STDIO, target.transport());
        assertEquals("java", target.command());
        assertEquals(java.util.List.of("-jar", "server.jar"), target.args());
        assertEquals(java.util.Map.of("API_KEY", "x"), target.env());
        assertEquals(Duration.ofSeconds(30), target.timeout());
    }

    @Test
    void httpConfigRequiresAUrl(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json");
        Files.writeString(config, """
                {"server":"s","transport":"streamable-http","command":"java"}""");

        IOException failure = org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                () -> ServerTarget.read(config));

        assertTrue(failure.getMessage().contains("url"), failure.getMessage());
    }

    @Test
    void stdioConfigStillRequiresACommand(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json");
        Files.writeString(config, """
                {"server":"s","url":"http://example.com/mcp"}""");

        IOException failure = org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                () -> ServerTarget.read(config));

        assertTrue(failure.getMessage().contains("command"), failure.getMessage());
    }

    @Test
    void describeTargetNeverLeaksHeaderValues(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json");
        Files.writeString(config, """
                {"server":"s","transport":"streamable-http","url":"https://mcp.example.com/mcp",
                 "headers":{"Authorization":"Bearer ${MCP_TOKEN}"}}""");

        ServerTarget target = ServerTarget.read(config);

        assertEquals("https://mcp.example.com/mcp", target.describeTarget());
        // 引用到的变量名可以被报出来（用于提示），但值本身不在对象里
        assertEquals(java.util.List.of("MCP_TOKEN"), target.referencedEnvVars());
        assertFalse(target.describeTarget().contains("Bearer"), target.describeTarget());
    }
}
