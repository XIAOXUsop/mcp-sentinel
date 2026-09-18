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
        if (root == null || !root.isObject()) {
            throw new IOException("基线文件不是 JSON 对象。"
                    + "这通常意味着文件被写坏或被别的工具覆盖。");
        }
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

        // 内容完整性：能解析成 JSON 不等于能用。
        // 一份 version 正确但 tools 缺失/为空的基线，会让「所有工具都是新增」或
        // 「一切正常」这类结论建立在空数据集上——后者尤其危险：扫描通过，门禁形同虚设。
        JsonNode toolsNode = root.path("tools");
        if (!toolsNode.isArray()) {
            throw new IOException("基线缺少 tools 数组（或类型不是数组）。"
                    + "基线必须完整保存被锁定的工具定义，否则无法做漂移比对。");
        }
        List<ToolEntry> tools = new ArrayList<>();
        for (JsonNode entry : toolsNode) {
            if (!entry.isObject()) {
                throw new IOException("基线 tools 中存在非对象条目：" + entry.getNodeType());
            }
            String name = entry.path("name").asText("");
            String fingerprint = entry.path("fingerprint").asText("");
            if (name.isBlank()) {
                throw new IOException("基线中有一个工具条目缺少 name 字段——"
                        + "无法确定它是谁，比对结果不可信。");
            }
            if (fingerprint.isBlank()) {
                throw new IOException("基线中工具 '" + name + "' 缺少 fingerprint 字段——"
                        + "「未变更」这一结论正是靠它得出的，缺了它就无法判定。");
            }
            tools.add(new ToolEntry(ToolDefinition.fromJson(entry), fingerprint));
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

    /**
     * 除 {@code generatedAt} 外，两份基线是否描述同一个工具面。
     *
     * <p><b>为什么需要它</b>：{@code --accept-changes} 在**没有变更可批准**时也会重写基线，
     * 而重写会让 {@code generatedAt} 变一次——于是 {@code git status} 里出现一条改动，
     * 但 diff 的内容是一行时间戳。评审者看到的是一次"工具面好像变了"，实际什么都没变。
     * 这个工具的立身之本是「配置被改了」要像「代码被改了」一样出现在 diff 里；
     * 反过来让「配置没变」看起来像变了，同样是在破坏这份契约。
     *
     * <p><b>为什么不直接用 record 的 equals</b>：{@link #of} 存的是**未经规范化**的原始定义，
     * 而 {@link #read} 从文件读回的是**已规范化**的形态（写出去时过了
     * {@link ToolDefinition#toJson()}）。两者描述同一个工具面，JsonNode 却不逐字节相等——
     * 直接比会让"内容没变"永远判成"变了"，修复等于没做。所以比指纹与规范化文本。
     */
    public boolean sameContentAs(Baseline other) {
        if (version != other.version
                || schemaVersion != other.schemaVersion
                || !java.util.Objects.equals(serverName, other.serverName)
                || !java.util.Objects.equals(surfaceFingerprint, other.surfaceFingerprint)
                || !acceptedChanges.equals(other.acceptedChanges)
                || tools.size() != other.tools.size()) {
            return false;
        }
        for (int i = 0; i < tools.size(); i++) {
            ToolEntry mine = tools.get(i);
            ToolEntry theirs = other.tools.get(i);
            if (!mine.fingerprint().equals(theirs.fingerprint())
                    || !mine.tool().canonicalForm().equals(theirs.tool().canonicalForm())) {
                return false;
            }
        }
        return true;
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
        Files.writeString(file, MAPPER.writer(prettyPrinter()).writeValueAsString(root),
                StandardCharsets.UTF_8);
    }

    /**
     * 让数组也逐元素换行。
     *
     * <p>默认的美化输出会把 {@code "tools" : [ {} } 挤在同一行，两个后果：
     * 一是这份"要提交进版本库、出现在评审里"的文件变得难读也难 diff；
     * 二是注解无法定位到具体工具所在的行（SARIF 的 {@code region.startLine} 需要真实行号）。
     */
    static com.fasterxml.jackson.core.util.DefaultPrettyPrinter prettyPrinter() {
        com.fasterxml.jackson.core.util.DefaultPrettyPrinter printer =
                new com.fasterxml.jackson.core.util.DefaultPrettyPrinter();
        printer.indentArraysWith(com.fasterxml.jackson.core.util.DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
        return printer;
    }

    // ---------- 对比 ----------

    /**
     * 与当前工具面比较，得出**带类型的变更集**。
     *
     * <p>重名工具按**出现序号**逐个配对——旧版以工具名为键，其中一个被改写会被另一个覆盖，
     * 于是改动被完全静默地吞掉。已批准的变更（指纹命中 {@code acceptedChanges}）
     * 会被标出来但不阻断 CI。
     */
    public SurfaceDiff diffAgainst(ToolSurface current) {
        Map<String, List<ToolEntry>> before = group(tools, entry -> entry.tool().name());
        Map<String, List<ToolDefinition>> after = group(current.sorted(), ToolDefinition::name);

        List<Change> changes = new ArrayList<>();
        for (Map.Entry<String, List<ToolDefinition>> entry : after.entrySet()) {
            List<ToolEntry> previous = before.get(entry.getKey());
            for (int i = 0; i < entry.getValue().size(); i++) {
                ToolDefinition now = entry.getValue().get(i);
                if (previous == null || i >= previous.size()) {
                    // 新增的工具是攻击面——rug pull 最常见的形态就是"多出来一个工具"
                    changes.add(new Change("TOOL_ADDED", entry.getKey(), i, ChangeSeverity.DANGEROUS,
                            "新增工具", ToolFingerprint.of(now).substring(0, 16)));
                    continue;
                }
                ToolDefinition was = previous.get(i).tool();
                if (!ToolFingerprint.of(now).equals(previous.get(i).fingerprint())) {
                    changes.addAll(SchemaDiff.between(was, now, i));
                }
            }
        }
        for (Map.Entry<String, List<ToolEntry>> entry : before.entrySet()) {
            List<ToolDefinition> currentTools = after.get(entry.getKey());
            int currentSize = currentTools == null ? 0 : currentTools.size();
            for (int i = currentSize; i < entry.getValue().size(); i++) {
                changes.add(new Change("TOOL_REMOVED", entry.getKey(), i, ChangeSeverity.BREAKING,
                        "工具被移除", entry.getValue().get(i).fingerprint().substring(0, 16)));
            }
        }
        return new SurfaceDiff(changes, approvedDigests());
    }

    /** 已批准的变更指纹集合 */
    public java.util.Set<String> approvedDigests() {
        java.util.Set<String> digests = new java.util.LinkedHashSet<>();
        for (AcceptedChange change : acceptedChanges) {
            digests.add(change.digest());
        }
        return digests;
    }

    private static <T> Map<String, List<T>> group(List<T> items, Function<T, String> nameOf) {
        Map<String, List<T>> grouped = new LinkedHashMap<>();
        for (T item : items) {
            grouped.computeIfAbsent(nameOf.apply(item), key -> new ArrayList<>()).add(item);
        }
        return new TreeMap<>(grouped);
    }
}
