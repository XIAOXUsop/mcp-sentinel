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
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 被扫描的 MCP 服务器目标。支持两种传输：stdio（本地子进程）与 Streamable HTTP（远程端点）。
 *
 * <p>stdio 的配置格式与主流 MCP 客户端保持一致，便于直接从现有配置里复制：
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
 * <p>Streamable HTTP：
 * <pre>
 * {
 *   "server": "my-remote-server",
 *   "transport": "streamable-http",
 *   "url": "https://mcp.example.com/mcp",
 *   "headers": { "Authorization": "Bearer ${MCP_TOKEN}" },
 *   "timeoutSeconds": 20
 * }
 * </pre>
 *
 * <p><b>请求头里的密钥用 {@code ${环境变量名}} 引用</b>，配置文件里不放明文。
 * 这不只是习惯问题：配置文件本身会被提交进版本库，而扫描器的输入恰恰是不可信的第三方配置——
 * 把令牌明文写进去，等于让"扫描别人的 MCP 服务器"顺手把自家令牌也交出去了。
 * 引用了不存在的环境变量会在连接前直接失败，而不是发一个空头出去。
 *
 * <p><b>{@code env} 是必需的</b>：它是 Claude Desktop / VS Code / Cursor 配置里的标准字段
 * （很多 server 靠它拿 API key），旧版忽略它——于是"可直接从现有配置复制"这个卖点
 * 在真实配置上会直接失败。
 *
 * <p><b>{@code cwd} 不支持</b>：MCP SDK 的 {@code ServerParameters} 没有暴露工作目录
 * （实测其 Builder 只有 command / args / env）。与其假装支持，不如在这里说清楚。
 */
public record ServerTarget(String serverName, Transport transport, String command, List<String> args,
                           Map<String, String> env, String url, Map<String, String> headers,
                           Duration timeout) {

    /** 默认请求超时。旧版把它硬编码在这里，连不上时要整整等满 20 秒 */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(20);

    /** 请求头里对同名环境变量的引用，例如 {@code Bearer ${MCP_TOKEN}} */
    private static final Pattern ENV_REFERENCE = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 连接方式 */
    public enum Transport {
        /** 起本地子进程，走 stdin/stdout 上的 JSON-RPC */
        STDIO,
        /** 远程端点，走 MCP Streamable HTTP */
        STREAMABLE_HTTP;

        /** 解析配置里的 transport 字段；缺省是 stdio，与主流客户端一致 */
        public static Transport parse(String value) throws IOException {
            if (value == null || value.isBlank()) {
                return STDIO;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT).replace('_', '-');
            return switch (normalized) {
                case "stdio" -> STDIO;
                case "streamable-http", "http", "sse" -> STREAMABLE_HTTP;
                default -> throw new IOException("不支持的 transport：'" + value + "'（只支持 stdio 与 streamable-http）");
            };
        }
    }

    public ServerTarget {
        args = args == null ? List.of() : List.copyOf(args);
        env = env == null ? Map.of() : Map.copyOf(env);
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
        Objects.requireNonNull(transport, "transport");
    }

    /** 只要命令与参数的简写（stdio；测试与最简单的配置用这个） */
    public ServerTarget(String serverName, String command, List<String> args) {
        this(serverName, Transport.STDIO, command, args, Map.of(), "", Map.of(), DEFAULT_TIMEOUT);
    }

    public static ServerTarget read(Path configFile) throws IOException {
        JsonNode root = MAPPER.readTree(Files.readString(configFile, StandardCharsets.UTF_8));
        Transport transport = Transport.parse(root.path("transport").asText(""));
        Duration timeout = root.hasNonNull("timeoutSeconds")
                ? Duration.ofSeconds(Math.max(1, root.path("timeoutSeconds").asLong(20)))
                : DEFAULT_TIMEOUT;

        if (transport == Transport.STREAMABLE_HTTP) {
            return readHttp(root, configFile, timeout);
        }
        return readStdio(root, configFile, timeout);
    }

    private static ServerTarget readStdio(JsonNode root, Path configFile, Duration timeout) throws IOException {
        String command = root.path("command").asText("");
        if (command.isBlank()) {
            throw new IOException("配置缺少 command 字段：" + configFile + "（这是 stdio 传输必需的）");
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
        String name = root.path("server").asText(command);
        return new ServerTarget(name, Transport.STDIO, command, args, env, "", Map.of(), timeout);
    }

    private static ServerTarget readHttp(JsonNode root, Path configFile, Duration timeout) throws IOException {
        String url = root.path("url").asText("");
        if (url.isBlank()) {
            throw new IOException("配置缺少 url 字段：" + configFile + "（这是 streamable-http 传输必需的）");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        JsonNode headersNode = root.path("headers");
        if (headersNode.isObject()) {
            headersNode.fields().forEachRemaining(entry -> headers.put(entry.getKey(), entry.getValue().asText()));
        }
        String name = root.path("server").asText(url);
        return new ServerTarget(name, Transport.STREAMABLE_HTTP, "", List.of(), Map.of(), url, headers, timeout);
    }

    /** 覆盖超时（命令行 {@code --timeout} 用） */
    public ServerTarget withTimeout(Duration override) {
        return new ServerTarget(serverName, transport, command, args, env, url, headers, override);
    }

    /** 请求头里引用到的环境变量名（供错误提示与测试使用） */
    public List<String> referencedEnvVars() {
        List<String> names = new ArrayList<>();
        for (String value : headers.values()) {
            Matcher matcher = ENV_REFERENCE.matcher(value);
            while (matcher.find()) {
                names.add(matcher.group(1));
            }
        }
        return names;
    }

    /**
     * 把请求头里的 {@code ${VAR}} 替换成实际值。
     *
     * @param lookup 变量名 → 值；找不到时返回 null
     * @throws IOException 引用了不存在的环境变量。**不静默发空头**——
     *                     空 Authorization 会让请求以 401 失败，而真正的原因（变量名写错）
     *                     就被埋进了一个看起来像"服务器拒绝"的错误里
     */
    public Map<String, String> resolveHeaders(Function<String, String> lookup) throws IOException {
        Map<String, String> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            Matcher matcher = ENV_REFERENCE.matcher(entry.getValue());
            StringBuilder value = new StringBuilder();
            while (matcher.find()) {
                String name = matcher.group(1);
                String replacement = lookup.apply(name);
                if (replacement == null) {
                    throw new IOException("请求头 '" + entry.getKey() + "' 引用的环境变量 " + name
                            + " 未设置。密钥不应写进配置文件，请通过环境变量注入。");
                }
                matcher.appendReplacement(value, Matcher.quoteReplacement(replacement));
            }
            matcher.appendTail(value);
            resolved.put(entry.getKey(), value.toString());
        }
        return resolved;
    }

    /** 配置里的目标描述，用于失败诊断；<b>不含请求头值</b>，避免密钥进日志 */
    public String describeTarget() {
        return transport == Transport.STDIO ? command + " " + String.join(" ", args) : url;
    }
}
