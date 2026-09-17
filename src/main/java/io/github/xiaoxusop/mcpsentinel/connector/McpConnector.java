package io.github.xiaoxusop.mcpsentinel.connector;

import io.github.xiaoxusop.mcpsentinel.ToolDefinition;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;
import io.github.xiaoxusop.mcpsentinel.ToolFingerprint;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    /** 异常到可读错误：消息为空时退回类名，避免报告里出现一个空白的"失败原因" */
    private static String failureMessage(Exception e) {
        String message = e.getMessage();
        return message == null || message.isBlank() ? e.getClass().getSimpleName() : message;
    }

    /**
     * 按配置里的传输方式建连接。
     *
     * <p>两种传输只在这一个方法里分叉：上面 {@link #connect} 之后的初始化、拉工具面、
     * 错误处理完全共用。规则、指纹、基线这些都不认识"传输"这个概念——
     * 换传输不该改变任何一条检测语义。
     */
    private static McpClientTransport buildTransport(ServerTarget target) throws Exception {
        if (target.transport() == ServerTarget.Transport.STREAMABLE_HTTP) {
            Map<String, String> headers = target.resolveHeaders(System::getenv);
            return HttpClientStreamableHttpTransport.builder(target.url())
                    .jsonMapper(McpJsonDefaults.getMapper())
                    .connectTimeout(target.timeout())
                    .httpRequestCustomizer((requestBuilder, method, uri, body, context) ->
                            headers.forEach(requestBuilder::header))
                    .build();
        }

        ServerParameters.Builder parameters = ServerParameters.builder(target.command())
                .args(target.args().toArray(new String[0]));
        // env 是主流客户端配置的标准字段，很多 server 靠它拿 API key；
        // 忽略它会让"可直接从现有配置复制"这个卖点在真实配置上直接失败
        if (!target.env().isEmpty()) {
            parameters.env(target.env());
        }
        return new StdioClientTransport(parameters.build(), McpJsonDefaults.getMapper());
    }

    public static Result connect(ServerTarget target) {
        McpClientTransport transport;
        try {
            transport = buildTransport(target);
        } catch (Exception e) {
            // 配置层面的问题（比如引用了不存在的环境变量）在连接之前就要说清楚
            return Result.failure(target.serverName(), failureMessage(e));
        }

        try (McpSyncClient client = McpClient
                .sync(transport)
                .clientInfo(new McpSchema.Implementation("mcp-sentinel", "0.3.0"))
                .requestTimeout(target.timeout() == null ? REQUEST_TIMEOUT : target.timeout())
                .build()) {

            McpSchema.InitializeResult handshake = client.initialize();
            String serverName = handshake != null && handshake.serverInfo() != null
                    ? handshake.serverInfo().name() : target.serverName();

            McpSchema.ListToolsResult listed = client.listTools();
            List<ToolDefinition> tools = new ArrayList<>();
            if (listed != null && listed.tools() != null) {
                for (McpSchema.Tool tool : listed.tools()) {
                    // 六个字段全都要：title / outputSchema / annotations 都是攻击面。
                    // 只取 name+description+inputSchema 时，单独翻转 destructiveHint
                    // 或改 outputSchema 的指纹完全不变——实测退出码 0，等于看不见。
                    tools.add(new ToolDefinition(
                            tool.name(),
                            tool.title(),
                            tool.description(),
                            toJson(tool.inputSchema()),
                            toJson(tool.outputSchema()),
                            toJson(tool.annotations())));
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
