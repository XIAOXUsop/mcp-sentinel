package io.github.xiaoxusop.mcpsentinel.connector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 被扫描的 MCP 服务器目标（stdio 传输）。
 *
 * <p>配置文件格式与主流 MCP 客户端保持一致，便于直接从现有配置里复制：
 * <pre>
 * {
 *   "server": "my-server",
 *   "command": "java",
 *   "args": ["-jar", "server.jar"],
 *   "env": { "API_KEY": "..." },
 *   "timeoutSeconds": 20
 * }
 * </pre>
 *
 * <p><b>{@code env} 是必需的</b>：它是 Claude Desktop / VS Code / Cursor 配置里的标准字段
 * （很多 server 靠它拿 API key），旧版忽略它——于是"可直接从现有配置复制"这个卖点
 * 在真实配置上会直接失败。
 *
 * <p><b>{@code cwd} 不支持</b>：MCP SDK 的 {@code ServerParameters} 没有暴露工作目录
 * （实测其 Builder 只有 command / args / env）。与其假装支持，不如在这里说清楚。
 */
public record ServerTarget(String serverName, String command, List<String> args,
                           Map<String, String> env, Duration timeout) {

    /** 默认请求超时。旧版把它硬编码在这里，连不上时要整整等满 20 秒 */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(20);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public ServerTarget {
        args = args == null ? List.of() : List.copyOf(args);
        env = env == null ? Map.of() : Map.copyOf(env);
        timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
    }

    /** 只要命令与参数的简写（测试与最简单的配置用这个） */
    public ServerTarget(String serverName, String command, List<String> args) {
        this(serverName, command, args, Map.of(), DEFAULT_TIMEOUT);
    }

    public static ServerTarget read(Path configFile) throws IOException {
        JsonNode root = MAPPER.readTree(Files.readString(configFile, StandardCharsets.UTF_8));
        String command = root.path("command").asText("");
        if (command.isBlank()) {
            throw new IOException("配置缺少 command 字段：" + configFile);
        }
        List<String> args = new ArrayList<>();
        JsonNode argsNode = root.path("args");
        if (argsNode.isArray()) {
            argsNode.forEach(node -> args.add(node.asText()));
        }
        Map<String, String> env = new LinkedHashMap<>();
        JsonNode envNode = root.path("env");
        if (envNode.isObject()) {
            envNode.fields().forEachRemaining(entry -> env.put(entry.getKey(), entry.getValue().asText()));
        }
        Duration timeout = root.hasNonNull("timeoutSeconds")
                ? Duration.ofSeconds(Math.max(1, root.path("timeoutSeconds").asLong(20)))
                : DEFAULT_TIMEOUT;

        String name = root.path("server").asText(command);
        return new ServerTarget(name, command, args, env, timeout);
    }

    /** 覆盖超时（命令行 {@code --timeout} 用） */
    public ServerTarget withTimeout(Duration override) {
        return new ServerTarget(serverName, command, args, env, override);
    }
}
