package io.github.xiaoxusop.mcpsentinel.connector;

import io.github.xiaoxusop.mcpsentinel.ToolDefinition;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;
import io.github.xiaoxusop.mcpsentinel.ToolFingerprint;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpAsyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import io.github.xiaoxusop.mcpsentinel.Version;
import io.github.xiaoxusop.mcpsentinel.BoundedInput;

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
    private static EvidenceTransport buildTransport(ServerTarget target) throws Exception {
        if (target.transport() == ServerTarget.Transport.STREAMABLE_HTTP) {
            Map<String, String> headers = target.resolveHeaders(System::getenv);
            return new EvidenceTransport(HttpClientStreamableHttpTransport.builder(target.url())
                    .jsonMapper(new BudgetJsonMapper())
                    .maxResponseSize(BoundedInput.MESSAGE_BYTES)
                    .connectTimeout(target.timeout())
                    .httpRequestCustomizer((requestBuilder, method, uri, body, context) ->
                            headers.forEach(requestBuilder::header))
                    .build());
        }

        target.resolveEnvironment(System::getenv);
        return new EvidenceTransport(new OwnedStdioTransport(target, new BudgetJsonMapper()));
    }

    public static Result connect(ServerTarget target) {
        try { return connectOwned(target); }
        catch (Exception e) {
            return Result.failure(target.serverName(), "CLEANUP", target.redactDiagnostic("连接或清理失败：" + failureMessage(e)));
        }
    }

    private static Result connectOwned(ServerTarget target) {
        EvidenceTransport transport;
        try {
            transport = buildTransport(target);
        } catch (Exception e) {
            // 配置层面的问题（比如引用了不存在的环境变量）在连接之前就要说清楚
            return Result.failure(target.serverName(), "CONFIGURATION", target.redactDiagnostic(failureMessage(e)));
        }

        String phase = "初始化";
        McpAsyncClient client = McpClient
                .async(transport)
                // 版本从 pom 过滤进来，不再手写——见 Version 的注释
                .clientInfo(new McpSchema.Implementation("mcp-sentinel", Version.value()))
                .requestTimeout(target.requestTimeout())
                .initializationTimeout(target.requestTimeout())
                .build();
        long deadline = System.nanoTime() + target.timeout().plus(target.requestTimeout().multipliedBy(2)).toNanos();
        try {

            McpSchema.InitializeResult handshake = client.initialize().block(remaining(deadline));
            if (handshake == null) return Result.failure(target.serverName(), "INITIALIZE", "初始化返回空响应，无法判定工具面");
            String serverName = handshake != null && handshake.serverInfo() != null
                    ? handshake.serverInfo().name() : target.serverName();

            phase = "工具列表请求";
            List<ToolDefinition> tools = new ArrayList<>();
            java.util.Set<String> cursors = new java.util.HashSet<>();
            String cursor = null;
            int pages = 0;
            long totalBytes = 0;
            do {
                if (++pages > 100) return Result.failure(target.serverName(), "工具列表分页超过安全上限 100 页");
                McpSchema.ListToolsResult listed = client.listTools(cursor).block(remaining(deadline));
                if (listed == null || listed.tools() == null) return Result.failure(target.serverName(), "工具列表返回空响应，无法判定工具面");
                EvidenceTransport.Page page = transport.takePage(listed);
                if ((long) tools.size() + page.tools().size() > target.maxTools()) {
                    return Result.failure(target.serverName(),
                            "服务器累计返回工具数超过安全上限 " + target.maxTools()
                                    + "（可通过 --max-tools 或配置中的 maxTools 调整）");
                }
                for (ToolDefinition def : page.tools()) {
                    int bytes = def.toRawJson().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                    if (bytes > ServerTarget.MAX_TOOL_DEFINITION_BYTES) {
                        return Result.failure(target.serverName(),
                                "工具 '" + def.name() + "' 定义大小 " + bytes
                                        + " 字节超过安全上限 " + ServerTarget.MAX_TOOL_DEFINITION_BYTES);
                    }
                    totalBytes += bytes;
                    if (totalBytes > 16 * 1024 * 1024) return Result.failure(target.serverName(), "累计工具定义超过安全上限 16 MiB");
                    def.canonicalForm();
                    tools.add(def);
                }
                cursor = page.cursor();
                if (cursor != null && (cursor.isBlank() || !cursors.add(cursor))) {
                    return Result.failure(target.serverName(), "工具分页 cursor 为空或重复；不能把未完成采集当成完整工具面");
                }
            } while (cursor != null);
            return Result.success(ToolSurface.of(serverName, tools), handshake.protocolVersion());
        } catch (Exception e) {
            return Result.failure(target.serverName(), "初始化".equals(phase) ? "INITIALIZE" : "COLLECT_TOOLS", target.redactDiagnostic(
                    phase + "失败（HTTP 连接超时=" + target.timeout().toSeconds()
                            + "s，请求超时=" + target.requestTimeout().toSeconds() + "s）："
                            + e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage())));
        } finally {
            try { client.closeGracefully().block(Duration.ofSeconds(2)); }
            catch (Exception e) {
                // Explicitly finish owned transport cleanup even when the SDK session cannot close.
                transport.closeGracefully().block(Duration.ofSeconds(2));
                throw new IllegalStateException("MCP 清理未在预算内完成", e);
            }
        }
    }

    private static Duration remaining(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) throw new IllegalStateException("采集超过总时间预算");
        return Duration.ofNanos(nanos);
    }

    /**
     * 连接结果。失败时携带可读原因，供报告直接展示。
     */
    public record Result(boolean ok, ToolSurface surface, String serverName, String error, String phase,
                         String protocolVersion) {

        public Result(boolean ok, ToolSurface surface, String serverName, String error, String phase) {
            this(ok, surface, serverName, error, phase, "");
        }

        static Result success(ToolSurface surface, String protocolVersion) {
            return new Result(true, surface, surface.serverName(), null, "COMPLETE", protocolVersion);
        }

        static Result failure(String serverName, String error) {
            return failure(serverName, "COLLECT_TOOLS", error);
        }

        static Result failure(String serverName, String phase, String error) {
            return new Result(false, null, serverName, error, phase);
        }

        public String shortFingerprint() {
            return surface == null ? "-" : ToolFingerprint.shortOf(surface.fingerprint());
        }
    }
}
