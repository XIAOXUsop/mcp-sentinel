package io.github.xiaoxusop.mcpsentinel.connector;

import io.github.xiaoxusop.mcpsentinel.ToolDefinition;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;
import io.github.xiaoxusop.mcpsentinel.ToolFingerprint;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * 通过 MCP 协议连到服务器，把工具面拉下来。
 *
 * <p>这是本项目中**唯一**依赖 MCP SDK 的部分：指纹与规则都是纯逻辑，
 * 因此即使 SDK 换版本或换传输，检测语义也不受影响。
 *
 * <p>连接失败不抛异常而是返回 {@link Result#failure}——扫描器本身要能在
 * 目标不可用时给出可读的诊断，而不是甩一个堆栈。
 */
public final class McpConnector {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(20);

    private McpConnector() {
    }

    public static Result connect(ServerTarget target) {
        ServerParameters parameters = ServerParameters.builder(target.command())
                .args(target.args().toArray(new String[0]))
                .build();

        try (McpSyncClient client = McpClient
                .sync(new StdioClientTransport(parameters, McpJsonDefaults.getMapper()))
                .clientInfo(new McpSchema.Implementation("mcp-sentinel", "0.1.0"))
                .requestTimeout(REQUEST_TIMEOUT)
                .build()) {

            McpSchema.InitializeResult handshake = client.initialize();
            String serverName = handshake != null && handshake.serverInfo() != null
                    ? handshake.serverInfo().name() : target.serverName();

            McpSchema.ListToolsResult listed = client.listTools();
            List<ToolDefinition> tools = new ArrayList<>();
            if (listed != null && listed.tools() != null) {
                for (McpSchema.Tool tool : listed.tools()) {
                    tools.add(new ToolDefinition(tool.name(), tool.description(), toJson(tool.inputSchema())));
                }
            }
            return Result.success(ToolSurface.of(serverName, tools));
        } catch (Exception e) {
            return Result.failure(target.serverName(),
                    e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()));
        }
    }

    /** schema 在 SDK 里是 Map，转成 JsonNode 以便规范化与指纹计算 */
    private static com.fasterxml.jackson.databind.JsonNode toJson(Object schema) {
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        return schema == null ? mapper.createObjectNode() : mapper.valueToTree(schema);
    }

    /**
     * 连接结果。失败时携带可读原因，供报告直接展示。
     */
    public record Result(boolean ok, ToolSurface surface, String serverName, String error) {

        static Result success(ToolSurface surface) {
            return new Result(true, surface, surface.serverName(), null);
        }

        static Result failure(String serverName, String error) {
            return new Result(false, null, serverName, error);
        }

        public String shortFingerprint() {
            return surface == null ? "-" : ToolFingerprint.shortOf(surface.fingerprint());
        }
    }
}
