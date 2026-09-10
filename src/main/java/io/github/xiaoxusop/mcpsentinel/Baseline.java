package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * 工具面基线：把"服务器当初长什么样"变成一份可提交、可评审的文件。
 *
 * <p>基线应当**提交进版本库**。这样"工具定义被改了"就会像"代码被改了"一样
 * 出现在 diff 与评审里——MCP 的 rug pull 攻击恰恰发生在没人看的运行时，
 * 把它搬进代码评审是最省事也最有效的防线。
 */
public record Baseline(int version, String serverName, String surfaceFingerprint,
                       String generatedAt, Map<String, String> toolFingerprints) {

    public static final int CURRENT_VERSION = 1;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public Baseline {
        toolFingerprints = Map.copyOf(toolFingerprints);
    }

    public static Baseline of(ToolSurface surface) {
        Map<String, String> map = new TreeMap<>();
        surface.sorted().forEach(tool -> map.put(tool.name(), ToolFingerprint.of(tool)));
        return new Baseline(CURRENT_VERSION, surface.serverName(), surface.fingerprint(),
                Instant.now().toString(), map);
    }

    public static Baseline read(Path file) throws IOException {
        JsonNode root = MAPPER.readTree(Files.readString(file, StandardCharsets.UTF_8));
        Map<String, String> tools = new TreeMap<>();
        JsonNode toolsNode = root.path("tools");
        if (toolsNode.isObject()) {
            toolsNode.fields().forEachRemaining(entry -> tools.put(entry.getKey(), entry.getValue().asText()));
        }
        return new Baseline(
                root.path("version").asInt(CURRENT_VERSION),
                root.path("server").asText("unknown"),
                root.path("surfaceFingerprint").asText(""),
                root.path("generatedAt").asText(""),
                tools);
    }

    public void write(Path file) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", version);
        root.put("_comment", "MCP 工具面基线。请提交进版本库：工具定义变化应当出现在 diff 与评审中。");
        root.put("server", serverName);
        root.put("surfaceFingerprint", surfaceFingerprint);
        root.put("generatedAt", generatedAt);
        ObjectNode tools = root.putObject("tools");
        new TreeMap<>(toolFingerprints).forEach(tools::put);
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        Files.writeString(file, MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root),
                StandardCharsets.UTF_8);
    }

    /** 与当前工具面比较，得出差异 */
    public SurfaceDiff diffAgainst(ToolSurface current) {
        Map<String, String> now = new LinkedHashMap<>();
        current.sorted().forEach(tool -> now.put(tool.name(), ToolFingerprint.of(tool)));

        Map<String, String> added = new TreeMap<>();
        Map<String, String> changed = new TreeMap<>();
        for (Map.Entry<String, String> entry : now.entrySet()) {
            String before = toolFingerprints.get(entry.getKey());
            if (before == null) {
                added.put(entry.getKey(), entry.getValue());
            } else if (!before.equals(entry.getValue())) {
                changed.put(entry.getKey(), entry.getValue());
            }
        }
        Map<String, String> removed = new TreeMap<>();
        toolFingerprints.forEach((name, fingerprint) -> {
            if (!now.containsKey(name)) {
                removed.put(name, fingerprint);
            }
        });
        return new SurfaceDiff(added, removed, changed);
    }
}
