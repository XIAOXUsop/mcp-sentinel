package io.github.xiaoxusop.mcpsentinel.connector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 被扫描的 MCP 服务器目标（stdio 传输）。
 *
 * <p>配置文件格式与主流 MCP 客户端保持一致，便于直接从现有配置里复制：
 * <pre>
 * {
 *   "server": "my-server",
 *   "command": "java",
 *   "args": ["-jar", "server.jar"]
 * }
 * </pre>
 */
public record ServerTarget(String serverName, String command, List<String> args) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public ServerTarget {
        args = args == null ? List.of() : List.copyOf(args);
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
        String name = root.path("server").asText(command);
        return new ServerTarget(name, command, args);
    }
}
