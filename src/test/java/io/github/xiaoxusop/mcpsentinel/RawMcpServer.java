package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 手写的、**不用 SDK** 的 MCP 服务器：按一份 JSON 描述回放工具面。
 *
 * <p>为什么不用官方 SDK 的服务端：本测试要构造的形态——重名工具、
 * 带换行的 {@code serverInfo.name}——用 SDK 起服务时**没能跑起来**
 * （实测报 "Client failed to initialize by explicit API call"）。
 * 而真实威胁模型里服务器是**不可信方**，它不会用 SDK 的校验约束自己；
 * 客户端必须能扛住这些东西。手写一个最小的 JSON-RPC 回放器才能测到这些输入。
 *
 * <p>用法：{@code RawMcpServer <描述文件.json>}，描述形如：
 * <pre>
 * { "serverName": "...", "tools": [ { "name": "...", "description": "...", "inputSchema": {...} } ] }
 * </pre>
 */
public final class RawMcpServer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private RawMcpServer() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("用法: RawMcpServer <描述文件.json>");
            System.exit(2);
        }
        JsonNode spec = MAPPER.readTree(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8));

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);

        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) {
                continue;
            }
            JsonNode request;
            try {
                request = MAPPER.readTree(line);
            } catch (Exception e) {
                continue;   // 不认识的输入直接忽略，别让服务器自己崩掉
            }
            JsonNode id = request.get("id");
            if (id == null || id.isNull()) {
                continue;   // 通知不需要回
            }
            String method = request.path("method").asText("");
            ObjectNode result = switch (method) {
                case "initialize" -> initializeResult(spec, request);
                case "tools/list" -> toolsResult(spec);
                default -> MAPPER.createObjectNode();   // 其余方法回空结果，够客户端继续
            };

            ObjectNode response = MAPPER.createObjectNode();
            response.put("jsonrpc", "2.0");
            response.set("id", id);
            response.set("result", result);
            out.println(MAPPER.writeValueAsString(response));
        }
    }

    private static ObjectNode initializeResult(JsonNode spec, JsonNode request) {
        ObjectNode result = MAPPER.createObjectNode();
        // 回显客户端请求的协议版本，免得因为版本不匹配被拒
        result.put("protocolVersion", request.path("params").path("protocolVersion").asText("2025-06-18"));
        result.putObject("capabilities").putObject("tools");
        ObjectNode serverInfo = result.putObject("serverInfo");
        serverInfo.put("name", spec.path("serverName").asText("raw-server"));
        serverInfo.put("version", "0.0.1");
        return result;
    }

    private static ObjectNode toolsResult(JsonNode spec) {
        ObjectNode result = MAPPER.createObjectNode();
        ArrayNode tools = result.putArray("tools");
        for (JsonNode tool : spec.path("tools")) {
            ObjectNode node = tools.addObject();
            node.put("name", tool.path("name").asText(""));
            if (tool.has("title")) {
                node.put("title", tool.path("title").asText(""));
            }
            node.put("description", tool.path("description").asText(""));
            node.set("inputSchema", tool.has("inputSchema")
                    ? tool.path("inputSchema")
                    : MAPPER.createObjectNode().put("type", "object"));
            if (tool.has("outputSchema")) {
                node.set("outputSchema", tool.path("outputSchema"));
            }
            if (tool.has("annotations")) {
                node.set("annotations", tool.path("annotations"));
            }
        }
        return result;
    }
}
