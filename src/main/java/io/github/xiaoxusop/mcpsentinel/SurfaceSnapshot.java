package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 离线工具面快照（W06）。
 *
 * <p>用于将一次采集到的工具定义保存为本地文件，支持后续在不启动 MCP 服务的情况下离线复跑
 * {@code scan --snapshot <file>}。
 *
 * <p>支持可选的脱敏导出（{@code redacted = true}）：将工具标题与描述脱敏后再分享给外部排障，
 * 但<b>脱敏副本在读取时会被严格标记，禁止用于 {@code lock}、{@code --accept-changes} 或基线漂移比对</b>，
 * 防止脱敏副本冒充原始指纹证据。
 */
public record SurfaceSnapshot(int version,
                              int schemaVersion,
                              String serverName,
                              boolean redacted,
                              String surfaceFingerprint,
                              String capturedAt,
                              List<ToolDefinition> tools,
                              String targetId) {

    public static final int CURRENT_VERSION = 1;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ObjectMapper STRICT_READER = JsonSupport.reader();

    public SurfaceSnapshot {
        tools = List.copyOf(tools);
    }

    public static SurfaceSnapshot of(ToolSurface surface, boolean redact) {
        return of(surface, redact, "server:" + surface.serverName());
    }

    public static SurfaceSnapshot of(ToolSurface surface, boolean redact, String targetId) {
        List<ToolDefinition> exported = new ArrayList<>();
        for (ToolDefinition tool : surface.sorted()) {
            if (redact) {
                exported.add(new ToolDefinition(
                        tool.name(),
                        tool.title().isBlank() ? "" : "[REDACTED len=" + tool.title().length() + "]",
                        tool.description().isBlank() ? "" : "[REDACTED len=" + tool.description().length() + "]",
                        tool.inputSchema(),
                        tool.outputSchema(),
                        tool.annotations()));
            } else {
                exported.add(tool);
            }
        }
        String fp = redact ? "REDACTED" : ToolFingerprint.ofSurface(exported);
        return new SurfaceSnapshot(CURRENT_VERSION, SchemaCanonicalizer.VERSION, surface.serverName(),
                redact, fp, Instant.now().toString(), exported, targetId);
    }

    public ToolSurface toSurface() {
        return ToolSurface.of(serverName, tools);
    }

    public static SurfaceSnapshot read(Path file) throws IOException {
        JsonNode root;
        try {
            root = STRICT_READER.readTree(io.github.xiaoxusop.mcpsentinel.BoundedInput.read(file));
        } catch (Exception e) {
            throw new IOException("快照 JSON 解析失败：" + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new IOException("快照文件不是 JSON 对象。");
        }
        JsonNode versionNode = root.path("version");
        if (!versionNode.isIntegralNumber() || !versionNode.canConvertToInt() || versionNode.intValue() != CURRENT_VERSION) {
            throw new IOException("快照格式版本不受支持（v" + versionNode.asText()
                    + "，当前支持 v" + CURRENT_VERSION + "）。");
        }
        JsonNode schemaVersionNode = root.path("schemaVersion");
        if (!schemaVersionNode.isIntegralNumber() || !schemaVersionNode.canConvertToInt() || schemaVersionNode.intValue() != SchemaCanonicalizer.VERSION) {
            throw new IOException("快照的规范化规则版本为 " + schemaVersionNode.asText()
                    + "，当前为 " + SchemaCanonicalizer.VERSION + "。");
        }
        if (!root.path("redacted").isBoolean()) throw new IOException("快照 redacted 必须为布尔值");
        for (String key : List.of("server", "capturedAt", "targetId")) {
            if (!root.path(key).isTextual() || root.path(key).textValue().isBlank()) throw new IOException("快照 " + key + " 必须为非空字符串");
        }
        boolean redacted = root.get("redacted").booleanValue();
        JsonNode toolsNode = root.path("tools");
        if (!toolsNode.isArray()) {
            throw new IOException("快照缺少 tools 数组。");
        }
        List<ToolDefinition> tools = new ArrayList<>();
        for (JsonNode entry : toolsNode) {
            if (!entry.isObject()) {
                throw new IOException("快照 tools 中存在非对象条目。");
            }
            String name = entry.path("name").asText("");
            if (name.isBlank()) {
                throw new IOException("快照中存在缺少 name 的工具条目。");
            }
            ToolDefinition tool = ToolDefinition.fromJson(entry);
            if (!redacted) {
                String recordedFp = entry.path("fingerprint").asText("");
                String recomputed = ToolFingerprint.of(tool);
                if (recordedFp.isBlank() || !recomputed.equals(recordedFp)) {
                    throw new IOException("快照中工具 '" + Sanitizer.forReport(name, 80)
                            + "' 的定义与记录的 fingerprint 不一致。");
                }
            }
            tools.add(tool);
        }
        String surfaceFingerprint = root.path("surfaceFingerprint").asText("");
        if (!redacted) {
            String expectedSurfaceFp = ToolFingerprint.ofSurface(tools);
            if (surfaceFingerprint.isBlank() || !expectedSurfaceFp.equals(surfaceFingerprint)) {
                throw new IOException("快照的 surfaceFingerprint 与工具列表重算结果不一致。");
            }
        }
        if (redacted && !"REDACTED".equals(surfaceFingerprint)) throw new IOException("脱敏快照必须明确标记指纹不可用");
        return new SurfaceSnapshot(
                CURRENT_VERSION,
                SchemaCanonicalizer.VERSION,
                root.path("server").asText("unknown"),
                redacted,
                surfaceFingerprint,
                root.path("capturedAt").asText(""),
                tools, root.get("targetId").textValue());
    }

    public void write(Path file) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", version);
        root.put("schemaVersion", schemaVersion);
        root.put("_notice", redacted
                ? "脱敏工具面快照（标题与描述已脱敏，不能作为原始指纹证据用于 lock 或基线漂移比对）。"
                : "MCP 工具面离线快照（可能包含敏感工具描述，公开分享前可使用 --redact 导出脱敏副本）。");
        root.put("server", serverName);
        root.put("targetId", targetId);
        root.put("redacted", redacted);
        root.put("surfaceFingerprint", surfaceFingerprint);
        root.put("capturedAt", capturedAt);

        ArrayNode toolsNode = root.putArray("tools");
        for (ToolDefinition tool : tools) {
            ObjectNode node = tool.toRawJson();
            if (!redacted) {
                node.put("fingerprint", ToolFingerprint.of(tool));
            }
            toolsNode.add(node);
        }

        String serialized = MAPPER.writer(Baseline.prettyPrinter()).writeValueAsString(root);
        AtomicFiles.write(file, serialized, SurfaceSnapshot::read);
    }
}
