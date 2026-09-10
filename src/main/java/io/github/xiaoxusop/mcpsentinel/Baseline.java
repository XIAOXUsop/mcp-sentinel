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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

/**
 * 工具面基线：把"服务器当初长什么样"变成一份可提交、可评审的文件。
 *
 * <p>基线应当**提交进版本库**。这样"工具定义被改了"就会像"代码被改了"一样
 * 出现在 diff 与评审里——MCP 的 rug pull 攻击恰恰发生在没人看的运行时，
 * 把它搬进代码评审是最省事也最有效的防线。
 *
 * <p><b>为什么存完整定义而不只是指纹</b>：
 * <ul>
 *   <li>只有指纹算不出"加了可选参数"与"加了必填参数"的区别——两者都只是"指纹变了"，
 *       而前者扩大攻击面、后者破坏调用方，安全含义完全相反；</li>
 *   <li>它同时是"**当初批准的是什么**"的证据：评审时能看到被批准的原始定义，
 *       而不只是一串哈希。</li>
 * </ul>
 * 代价是文件变大。这是语义分级能力的必要成本。
 *
 * <p><b>为什么工具是数组而不是以名字为键的对象</b>：旧版用 {@code Map<String,String>}，
 * 遇到重名会互相覆盖，于是对其中一个的修改被完全静默地吞掉——实测把投毒工具命名为
 * 与既有工具同名即可永久免疫漂移检测，退出码 0。数组形态天然容纳重名。
 */
public record Baseline(int version,
                       int schemaVersion,
                       String serverName,
                       String surfaceFingerprint,
                       String generatedAt,
                       List<ToolEntry> tools,
                       List<AcceptedChange> acceptedChanges) {

    /** 当前基线格式版本。1 = 旧的「以名字为键、只存指纹」形态 */
    public static final int CURRENT_VERSION = 2;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 一条被锁定的工具。
     *
     * @param tool        规范化后的完整定义——语义分级的输入，也是"批准了什么"的证据
     * @param fingerprint 该工具的指纹，便于人读而不必自己算
     */
    public record ToolEntry(ToolDefinition tool, String fingerprint) {

        public static ToolEntry of(ToolDefinition tool) {
            return new ToolEntry(tool, ToolFingerprint.of(tool));
        }
    }

    /**
     * 一条**已被接受**的变更。
     *
     * @param digest 变更指纹，跨 commit 稳定——同一个变更在后续提交里仍然算已批准，
     *               这样就不会因为"改了别的东西"而需要重新批准一遍
     */
    public record AcceptedChange(String id, String toolName, String digest) {
    }

    public Baseline {
        tools = List.copyOf(tools);
        acceptedChanges = List.copyOf(acceptedChanges);
    }

    public static Baseline of(ToolSurface surface) {
        return of(surface, List.of());
    }

    public static Baseline of(ToolSurface surface, List<AcceptedChange> acceptedChanges) {
        List<ToolEntry> entries = surface.sorted().stream().map(ToolEntry::of).toList();
        return new Baseline(CURRENT_VERSION, SchemaCanonicalizer.VERSION, surface.serverName(),
                surface.fingerprint(), Instant.now().toString(), entries, acceptedChanges);
    }

    // ---------- 读写 ----------

    public static Baseline read(Path file) throws IOException {
        JsonNode root = MAPPER.readTree(Files.readString(file, StandardCharsets.UTF_8));
        int version = root.path("version").asInt(1);
        if (version < CURRENT_VERSION) {
            throw new IOException("基线格式过旧（v" + version + "，当前 v" + CURRENT_VERSION + "）。"
                    + "旧格式以工具名为键存储，遇到重名会静默丢失条目——"
                    + "请重新运行 `mcp-sentinel lock` 生成新基线。");
        }
        int schemaVersion = root.path("schemaVersion").asInt(0);
        if (schemaVersion != SchemaCanonicalizer.VERSION) {
            throw new IOException("基线的规范化规则版本为 " + schemaVersion
                    + "，当前为 " + SchemaCanonicalizer.VERSION
                    + "。规则升级会让旧基线产生一次全量假变更，"
                    + "请重新运行 `mcp-sentinel lock`（这不是攻击）。");
        }

        List<ToolEntry> tools = new ArrayList<>();
        JsonNode toolsNode = root.path("tools");
        if (toolsNode.isArray()) {
            for (JsonNode entry : toolsNode) {
                tools.add(new ToolEntry(ToolDefinition.fromJson(entry), entry.path("fingerprint").asText("")));
            }
        }
        List<AcceptedChange> accepted = new ArrayList<>();
        JsonNode acceptedNode = root.path("acceptedChanges");
        if (acceptedNode.isArray()) {
            for (JsonNode node : acceptedNode) {
                accepted.add(new AcceptedChange(node.path("id").asText(""),
                        node.path("tool").asText(""), node.path("digest").asText("")));
            }
        }
        return new Baseline(version, schemaVersion,
                root.path("server").asText("unknown"),
                root.path("surfaceFingerprint").asText(""),
                root.path("generatedAt").asText(""),
                tools, accepted);
    }

    public void write(Path file) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", version);
        root.put("schemaVersion", schemaVersion);
        root.put("_comment", "MCP 工具面基线。请提交进版本库：工具定义变化应当出现在 diff 与评审中。"
                + "存的是规范化后的完整定义——它既是变更分级的输入，也是「当初批准的是什么」的证据。");
        root.put("server", serverName);
        root.put("surfaceFingerprint", surfaceFingerprint);
        root.put("generatedAt", generatedAt);

        ArrayNode toolsNode = root.putArray("tools");
        for (ToolEntry entry : tools) {
            ObjectNode node = entry.tool().toJson();
            node.put("fingerprint", entry.fingerprint());
            toolsNode.add(node);
        }

        ArrayNode acceptedNode = root.putArray("acceptedChanges");
        for (AcceptedChange change : acceptedChanges) {
            ObjectNode node = acceptedNode.addObject();
            node.put("id", change.id());
            node.put("tool", change.toolName());
            node.put("digest", change.digest());
        }

        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        Files.writeString(file, MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root),
                StandardCharsets.UTF_8);
    }

    // ---------- 对比 ----------

    /** 与当前工具面比较，得出差异。重名工具按**出现序号**逐个配对，不再互相覆盖 */
    public SurfaceDiff diffAgainst(ToolSurface current) {
        Map<String, List<ToolEntry>> before = group(tools, entry -> entry.tool().name());
        Map<String, List<ToolDefinition>> after = group(current.sorted(), ToolDefinition::name);

        List<String> added = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        List<SurfaceDiff.ModifiedTool> changed = new ArrayList<>();

        for (Map.Entry<String, List<ToolDefinition>> entry : after.entrySet()) {
            List<ToolEntry> previous = before.get(entry.getKey());
            for (int i = 0; i < entry.getValue().size(); i++) {
                if (previous == null || i >= previous.size()) {
                    added.add(entry.getKey());
                    continue;
                }
                ToolDefinition now = entry.getValue().get(i);
                String fingerprint = ToolFingerprint.of(now);
                if (!fingerprint.equals(previous.get(i).fingerprint())) {
                    changed.add(new SurfaceDiff.ModifiedTool(entry.getKey(), i,
                            previous.get(i).tool(), now));
                }
            }
        }
        for (Map.Entry<String, List<ToolEntry>> entry : before.entrySet()) {
            List<ToolDefinition> current2 = after.get(entry.getKey());
            int currentSize = current2 == null ? 0 : current2.size();
            for (int i = currentSize; i < entry.getValue().size(); i++) {
                removed.add(entry.getKey());
            }
        }
        return new SurfaceDiff(added, removed, changed);
    }

    private static <T> Map<String, List<T>> group(List<T> items, Function<T, String> nameOf) {
        Map<String, List<T>> grouped = new LinkedHashMap<>();
        for (T item : items) {
            grouped.computeIfAbsent(nameOf.apply(item), key -> new ArrayList<>()).add(item);
        }
        return new TreeMap<>(grouped);
    }
}
