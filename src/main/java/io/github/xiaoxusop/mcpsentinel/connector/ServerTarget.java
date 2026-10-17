package io.github.xiaoxusop.mcpsentinel.connector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.net.URI;
import java.util.Set;
import io.github.xiaoxusop.mcpsentinel.ToolFingerprint;
import io.github.xiaoxusop.mcpsentinel.JsonSupport;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 被扫描的 MCP 服务器目标。支持两种传输：stdio（本地子进程）与 Streamable HTTP（远程端点），
 * 同时支持单目标格式与主流客户端 {@code mcpServers} 多目标格式导入（W07 / W08）。
 */
public record ServerTarget(String serverName, Transport transport, String command, List<String> args,
                           Map<String, String> env, String url, Map<String, String> headers,
                           Duration timeout, Duration requestTimeout, int maxTools) {

    /** 默认请求超时 */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(20);

    /** 默认单服务最大允许采集的工具数量上限（W08 资源保护） */
    public static final int DEFAULT_MAX_TOOLS = 1000;

    /** 单个工具定义允许的最大 UTF-8 字节数（1 MiB，W08 资源保护） */
    public static final int MAX_TOOL_DEFINITION_BYTES = 1024 * 1024;

    /** 请求头里对同名环境变量的引用，例如 {@code Bearer ${MCP_TOKEN}} */
    private static final Pattern ENV_REFERENCE = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}");

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ObjectMapper STRICT_READER = JsonSupport.reader();

    /** 连接方式 */
    public enum Transport {
        /** 起本地子进程，走 stdin/stdout 上的 JSON-RPC */
        STDIO,
        /** 远程端点，走 MCP Streamable HTTP */
        STREAMABLE_HTTP;

        public static Transport parse(String value) throws IOException {
            if (value == null || value.isBlank()) {
                return STDIO;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT).replace('_', '-');
            return switch (normalized) {
                case "stdio" -> STDIO;
                case "streamable-http", "http" -> STREAMABLE_HTTP;
                case "sse" -> throw new IOException(
                        "transport 'sse' 是 MCP 早期的 HTTP+SSE 传输，与 streamable-http 不是一套协议，"
                                + "本工具暂不支持。若你的服务器用的是 Streamable HTTP，请写 streamable-http；"
                                + "若它确实只支持 SSE，请改用别的客户端或在服务器侧开启 Streamable HTTP。");
                default -> throw new IOException("不支持的 transport：'" + value + "'（只支持 stdio 与 streamable-http）");
            };
        }
    }

    public ServerTarget {
        args = args == null ? List.of() : List.copyOf(args);
        env = env == null ? Map.of() : Map.copyOf(env);
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
        requestTimeout = requestTimeout == null ? timeout : requestTimeout;
        maxTools = maxTools <= 0 ? DEFAULT_MAX_TOOLS : maxTools;
        Objects.requireNonNull(transport, "transport");
    }

    public ServerTarget(String serverName, Transport transport, String command, List<String> args,
                        Map<String, String> env, String url, Map<String, String> headers,
                        Duration timeout, Duration requestTimeout) {
        this(serverName, transport, command, args, env, url, headers, timeout, requestTimeout, DEFAULT_MAX_TOOLS);
    }

    public ServerTarget(String serverName, Transport transport, String command, List<String> args,
                        Map<String, String> env, String url, Map<String, String> headers, Duration timeout) {
        this(serverName, transport, command, args, env, url, headers, timeout, timeout, DEFAULT_MAX_TOOLS);
    }

    public ServerTarget(String serverName, String command, List<String> args) {
        this(serverName, Transport.STDIO, command, args, Map.of(), "", Map.of(),
                DEFAULT_TIMEOUT, DEFAULT_TIMEOUT, DEFAULT_MAX_TOOLS);
    }

    public static ServerTarget read(Path configFile) throws IOException {
        return read(configFile, null);
    }

    public static ServerTarget read(Path configFile, String selectedServer) throws IOException {
        JsonNode root = parseConfigRoot(configFile);
        if (root.has("mcpServers")) {
            List<ServerTarget> all = readMcpServersNode(root.get("mcpServers"), configFile);
            List<String> names = all.stream().map(ServerTarget::serverName).toList();
            if (selectedServer != null && !selectedServer.isBlank()) {
                return all.stream()
                        .filter(t -> t.serverName().equals(selectedServer))
                        .findFirst()
                        .orElseThrow(() -> new IOException("配置文件 " + configFile
                                + " 的 mcpServers 中找不到目标 '" + selectedServer + "'（可用目标：" + names + "）"));
            }
            if (all.size() == 1) {
                return all.get(0);
            }
            throw new IOException("配置文件 " + configFile + " 含多个 mcpServers 目标 " + names
                    + "，请用 `--server <名称>` 选择单个目标，或用 `--all-targets` 扫描全部目标。");
        }
        if (selectedServer != null && !selectedServer.isBlank()) {
            ServerTarget single = readSingleNode(root, null, configFile);
            if (!single.serverName().equals(selectedServer)) {
                throw new IOException("配置文件仅含单个目标 '" + single.serverName()
                        + "'，与请求的 --server '" + selectedServer + "' 不匹配。");
            }
            return single;
        }
        return readSingleNode(root, null, configFile);
    }

    /**
     * 读取配置文件中的全部目标（支持单目标格式或 {@code mcpServers} 多目标格式）。
     */
    public static List<ServerTarget> readAll(Path configFile) throws IOException {
        JsonNode root = parseConfigRoot(configFile);
        if (root.has("mcpServers")) {
            return readMcpServersNode(root.get("mcpServers"), configFile);
        }
        return List.of(readSingleNode(root, null, configFile));
    }

    private static JsonNode parseConfigRoot(Path configFile) throws IOException {
        JsonNode root;
        try {
            root = STRICT_READER.readTree(Files.readString(configFile, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IOException("解析配置文件失败：" + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new IOException("配置文件不是 JSON 对象：" + configFile);
        }
        return root;
    }

    private static List<ServerTarget> readMcpServersNode(JsonNode serversNode, Path configFile) throws IOException {
        if (serversNode == null || !serversNode.isObject()) {
            throw new IOException("配置文件中的 mcpServers 必须是 JSON 对象：" + configFile);
        }
        Map<String, JsonNode> sorted = new TreeMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = serversNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            sorted.put(entry.getKey(), entry.getValue());
        }
        if (sorted.isEmpty()) {
            throw new IOException("配置文件中的 mcpServers 不能为空：" + configFile);
        }
        List<ServerTarget> targets = new ArrayList<>();
        for (Map.Entry<String, JsonNode> entry : sorted.entrySet()) {
            String key = entry.getKey();
            JsonNode value = entry.getValue();
            if (value == null || !value.isObject()) {
                throw new IOException("mcpServers 中目标 '" + key + "' 的定义不是 JSON 对象：" + configFile);
            }
            if (value.has("disabled") && !value.get("disabled").isBoolean()) throw new IOException("disabled 必须为布尔值");
            if (value.path("disabled").asBoolean(false)) {
                continue;
            }
            targets.add(readSingleNode(value, key, configFile));
        }
        if (targets.isEmpty()) {
            throw new IOException("mcpServers 中的所有目标均处于 disabled 状态：" + configFile);
        }
        return targets;
    }

    private static ServerTarget readSingleNode(JsonNode root, String fallbackName, Path configFile) throws IOException {
        Set<String> supported = Set.of("server", "transport", "type", "command", "args", "env", "url", "headers",
                "timeoutSeconds", "connectTimeoutSeconds", "requestTimeoutSeconds", "maxTools", "disabled");
        var keys = root.fieldNames();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!supported.contains(key)) throw new IOException("不支持的配置字段 " + key + "；导入不会静默丢弃配置");
        }
        for (String key : List.of("server", "transport", "type", "command", "url")) {
            if (root.has(key) && !root.get(key).isTextual()) throw new IOException(key + " 必须为字符串");
        }
        for (String key : List.of("timeoutSeconds", "connectTimeoutSeconds", "requestTimeoutSeconds", "maxTools")) {
            if (root.has(key) && (!root.get(key).isIntegralNumber() || !root.get(key).canConvertToInt()
                    || root.get(key).intValue() < 1)) throw new IOException(key + " 必须为正整数");
            if (root.has(key) && !"maxTools".equals(key) && root.get(key).intValue() > 86400) throw new IOException(key + " 不能超过 86400 秒");
        }
        if (root.has("disabled") && !root.get("disabled").isBoolean()) throw new IOException("disabled 必须为布尔值");
        if (root.has("args")) {
            if (!root.get("args").isArray()) throw new IOException("args 必须为字符串数组");
            for (JsonNode item : root.get("args")) if (!item.isTextual()) throw new IOException("args 必须为字符串数组");
        }
        for (String key : List.of("env", "headers")) {
            if (root.has(key)) {
                if (!root.get(key).isObject()) throw new IOException(key + " 必须为字符串映射");
                for (JsonNode value : root.get(key)) if (!value.isTextual()) throw new IOException(key + " 必须为字符串映射");
            }
        }
        String rawTransport = root.path("transport").asText(root.path("type").asText(""));
        if (fallbackName != null && rawTransport.isBlank() && root.hasNonNull("url") && !root.hasNonNull("command")) {
            rawTransport = "streamable-http";
        }
        Transport transport = Transport.parse(rawTransport);
        Duration timeout = root.hasNonNull("timeoutSeconds")
                ? Duration.ofSeconds(Math.max(1, root.path("timeoutSeconds").asLong(20)))
                : DEFAULT_TIMEOUT;
        Duration connectTimeout = root.hasNonNull("connectTimeoutSeconds")
                ? Duration.ofSeconds(Math.max(1, root.path("connectTimeoutSeconds").asLong(20)))
                : timeout;
        Duration requestTimeout = root.hasNonNull("requestTimeoutSeconds")
                ? Duration.ofSeconds(Math.max(1, root.path("requestTimeoutSeconds").asLong(20)))
                : timeout;
        int maxTools = root.hasNonNull("maxTools")
                ? Math.max(1, root.path("maxTools").asInt(DEFAULT_MAX_TOOLS))
                : DEFAULT_MAX_TOOLS;

        if (transport == Transport.STREAMABLE_HTTP) {
            return readHttp(root, fallbackName, configFile, connectTimeout, requestTimeout, maxTools);
        }
        return readStdio(root, fallbackName, configFile, connectTimeout, requestTimeout, maxTools);
    }

    private static ServerTarget readStdio(JsonNode root, String fallbackName, Path configFile,
                                          Duration connectTimeout, Duration requestTimeout,
                                          int maxTools) throws IOException {
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
        String defaultName = (fallbackName != null && !fallbackName.isBlank()) ? fallbackName : command;
        String name = fallbackName != null ? fallbackName : root.path("server").asText(defaultName);
        if (name.isBlank()) throw new IOException("server 必须为非空字符串");
        return new ServerTarget(name, Transport.STDIO, command, args, env, "", Map.of(),
                connectTimeout, requestTimeout, maxTools);
    }

    private static ServerTarget readHttp(JsonNode root, String fallbackName, Path configFile,
                                         Duration connectTimeout, Duration requestTimeout,
                                         int maxTools) throws IOException {
        String url = root.path("url").asText("");
        if (url.isBlank()) {
            throw new IOException("配置缺少 url 字段：" + configFile + "（这是 streamable-http 传输必需的）");
        }
        try {
            URI endpoint = URI.create(url);
            if (!("http".equalsIgnoreCase(endpoint.getScheme()) || "https".equalsIgnoreCase(endpoint.getScheme()))
                    || endpoint.getHost() == null) throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) {
            throw new IOException("url 必须为有效的 http 或 https 绝对地址");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        JsonNode headersNode = root.path("headers");
        if (headersNode.isObject()) {
            headersNode.fields().forEachRemaining(entry -> headers.put(entry.getKey(), entry.getValue().asText()));
        }
        String defaultName = (fallbackName != null && !fallbackName.isBlank()) ? fallbackName : origin(url);
        String name = fallbackName != null ? fallbackName : root.path("server").asText(defaultName);
        if (name.isBlank()) throw new IOException("server 必须为非空字符串");
        return new ServerTarget(name, Transport.STREAMABLE_HTTP, "", List.of(), Map.of(), url, headers,
                connectTimeout, requestTimeout, maxTools);
    }

    /**
     * 导出标准化单目标配置 JSON（保留 {@code ${ENV_VAR}} 引用，不启动服务）。
     */
    public String toNormalizedJson() {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("server", serverName);
        if (transport == Transport.STREAMABLE_HTTP) {
            root.put("transport", "streamable-http");
            root.put("url", url);
            if (!headers.isEmpty()) {
                ObjectNode h = root.putObject("headers");
                headers.forEach(h::put);
            }
        } else {
            root.put("transport", "stdio");
            root.put("command", command);
            ArrayNode a = root.putArray("args");
            args.forEach(a::add);
            if (!env.isEmpty()) {
                ObjectNode e = root.putObject("env");
                env.forEach(e::put);
            }
        }
        root.put("connectTimeoutSeconds", timeout.toSeconds());
        root.put("requestTimeoutSeconds", requestTimeout.toSeconds());
        if (maxTools != DEFAULT_MAX_TOOLS) {
            root.put("maxTools", maxTools);
        }
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            throw new IllegalStateException("序列化标准化配置失败", e);
        }
    }

    public ServerTarget withTimeout(Duration override) {
        return new ServerTarget(serverName, transport, command, args, env, url, headers,
                override, override, maxTools);
    }

    public ServerTarget withConnectTimeout(Duration override) {
        return new ServerTarget(serverName, transport, command, args, env, url, headers,
                override, requestTimeout, maxTools);
    }

    public ServerTarget withRequestTimeout(Duration override) {
        return new ServerTarget(serverName, transport, command, args, env, url, headers,
                timeout, override, maxTools);
    }

    public ServerTarget withMaxTools(int override) {
        return new ServerTarget(serverName, transport, command, args, env, url, headers,
                timeout, requestTimeout, override);
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
        return transport == Transport.STDIO ? command + "（参数值不进入诊断日志）" : origin(url);
    }

    /** Namespace and non-secret origin/command, excluding headers, env and arguments. */
    public String identity() {
        String endpoint = transport == Transport.STDIO ? command : origin(url);
        return "target:" + ToolFingerprint.sha256(serverName + "\n" + transport + "\n" + endpoint);
    }

    private static String origin(String url) {
        URI uri = URI.create(url);
        return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT)
                + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
    }

    public Map<String, String> resolveEnvironment(Function<String, String> lookup) throws IOException {
        Map<String, String> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : env.entrySet()) {
            Matcher matcher = ENV_REFERENCE.matcher(entry.getValue());
            StringBuilder value = new StringBuilder();
            while (matcher.find()) {
                String replacement = lookup.apply(matcher.group(1));
                if (replacement == null) throw new IOException("env 引用的环境变量 " + matcher.group(1) + " 未设置");
                matcher.appendReplacement(value, Matcher.quoteReplacement(replacement));
            }
            matcher.appendTail(value);
            resolved.put(entry.getKey(), value.toString());
        }
        return resolved;
    }

    /** Remove configured credentials, argument values and endpoints from diagnostics. */
    public String redactDiagnostic(String message) {
        String safe = message == null ? "未知采集错误" : message;
        safe = safe.replaceAll("https?://[^\\s\\\"'<>]+", "[ENDPOINT]");
        List<String> values = new ArrayList<>(args);
        values.addAll(env.values());
        values.addAll(headers.values());
        try { values.addAll(resolveEnvironment(System::getenv).values()); } catch (IOException ignored) { }
        try { values.addAll(resolveHeaders(System::getenv).values()); } catch (IOException ignored) { }
        List<String> secrets = new ArrayList<>(values);
        for (String value : values) {
            if (value.regionMatches(true, 0, "Bearer ", 0, 7)) secrets.add(value.substring(7));
            if (value.regionMatches(true, 0, "Basic ", 0, 6)) secrets.add(value.substring(6));
        }
        secrets.sort(java.util.Comparator.comparingInt(String::length).reversed());
        for (String value : secrets) if (!value.isEmpty()) safe = safe.replace(value, "[REDACTED]");
        return safe;
    }
}
