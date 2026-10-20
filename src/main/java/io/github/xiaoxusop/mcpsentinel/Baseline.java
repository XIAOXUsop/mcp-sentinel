package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.nio.channels.OverlappingFileLockException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

/**
 * 工具面基线：把"服务器当初长什么样"变成一份可提交、可评审、自校验的文件。
 *
 * <p>信任链与完整性保护（W03 / F05 / F08）：
 * <ul>
 *   <li>读取时开启 Jackson 严格重复键检测（{@code STRICT_DUPLICATE_DETECTION}），拒绝重复字段覆盖；</li>
 *   <li>严格匹配 {@code version == CURRENT_VERSION} 与 {@code schemaVersion == SchemaCanonicalizer.VERSION}，
 *       显式拒绝旧版本与未来版本（如 {@code version=999}）；</li>
 *   <li>读取时根据保存的工具定义重新计算每个工具的 SHA-256 指纹及整体 {@code surfaceFingerprint}，
 *       任何定义与指纹不一致（改了定义却未更新指纹）一律拒绝加载；</li>
 *   <li>写入时采用同目录临时文件 → 序列化落盘 → 回读完整性校验 → 原子替换（{@code ATOMIC_MOVE}），
 *       失败时保留旧基线文件不被破坏。</li>
 * </ul>
 */
public record Baseline(int version,
                       int schemaVersion,
                       String serverName,
                       String surfaceFingerprint,
                       String generatedAt,
                       List<ToolEntry> tools,
                       List<AcceptedChange> acceptedChanges,
                       String targetId) {

    /** v3 保存采集原文，并绑定配置目标与审批的前后快照。 */
    public static final int CURRENT_VERSION = 3;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ObjectMapper STRICT_READER = JsonSupport.reader();

    /**
     * 一条被锁定的工具。
     */
    public record ToolEntry(ToolDefinition tool, String fingerprint) {

        public static ToolEntry of(ToolDefinition tool) {
            return new ToolEntry(tool, ToolFingerprint.of(tool));
        }
    }

    /**
     * 一条<b>已被接受</b>的变更。
     */
    public record AcceptedChange(String id, String toolName, String digest,
                                 String targetId, String beforeFingerprint, String afterFingerprint) {
    }

    public Baseline {
        tools = List.copyOf(tools);
        acceptedChanges = List.copyOf(acceptedChanges);
    }

    public static Baseline of(ToolSurface surface) {
        return of(surface, List.of());
    }

    public static Baseline of(ToolSurface surface, List<AcceptedChange> acceptedChanges) {
        return of(surface, "server:" + surface.serverName(), acceptedChanges);
    }

    public static Baseline of(ToolSurface surface, String targetId, List<AcceptedChange> acceptedChanges) {
        List<ToolEntry> entries = surface.sorted().stream().map(ToolEntry::of).toList();
        return new Baseline(CURRENT_VERSION, SchemaCanonicalizer.VERSION, surface.serverName(),
                surface.fingerprint(), Instant.now().toString(), entries, acceptedChanges, targetId);
    }

    // ---------- 读写 ----------

    public static Baseline read(Path file) throws IOException {
        JsonNode root;
        try {
            root = STRICT_READER.readTree(io.github.xiaoxusop.mcpsentinel.BoundedInput.read(file));
        } catch (Exception e) {
            throw new IOException("基线 JSON 解析失败（可能含语法错误或重复 JSON 键）：" + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new IOException("基线文件不是 JSON 对象。"
                    + "这通常意味着文件被写坏或被别的工具覆盖。");
        }
        JsonNode versionNode = root.path("version");
        int version = versionNode.isIntegralNumber() && versionNode.canConvertToInt() ? versionNode.intValue() : -1;
        if (version < CURRENT_VERSION) {
            throw new IOException("基线格式过旧（v" + version + "，当前 v" + CURRENT_VERSION + "）。"
                    + "v1 对重名不安全；v2 规范化可能已丢失 oneOf 重复项和 enum 内层顺序，且未绑定目标。"
                    + "请保留原文件，从可信服务重新运行 `mcp-sentinel lock` 并审阅新基线，不能静默迁移。");
        }
        if (version > CURRENT_VERSION || !versionNode.isIntegralNumber()) {
            throw new IOException("基线格式版本不受支持（v" + versionNode.asText() + "，当前最高支持 v"
                    + CURRENT_VERSION + "）。请升级 mcp-sentinel，不要用旧版工具读取未来格式。");
        }

        JsonNode schemaVersionNode = root.path("schemaVersion");
        int schemaVersion = schemaVersionNode.isIntegralNumber() && schemaVersionNode.canConvertToInt()
                ? schemaVersionNode.intValue() : 0;
        if (schemaVersion != SchemaCanonicalizer.VERSION) {
            throw new IOException("基线的规范化规则版本为 " + schemaVersion
                    + "，当前为 " + SchemaCanonicalizer.VERSION
                    + "。规则升级会让旧基线产生一次全量假变更（且旧规范化可能已丢失 oneOf 重复分支或 enum 内层顺序），"
                    + "请从可信服务重新运行 `mcp-sentinel lock`（这不是攻击）。");
        }

        JsonNode toolsNode = root.path("tools");
        if (!toolsNode.isArray()) {
            throw new IOException("基线缺少 tools 数组（或类型不是数组）。"
                    + "基线必须完整保存被锁定的工具定义，否则无法做漂移比对。");
        }
        List<ToolEntry> tools = new ArrayList<>();
        List<ToolDefinition> definitions = new ArrayList<>();
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
                throw new IOException("基线中工具 '" + Sanitizer.forReport(name, 80) + "' 缺少 fingerprint 字段——"
                        + "「未变更」这一结论正是靠它得出的，缺了它就无法判定。");
            }
            ToolDefinition tool;
            try {
                tool = ToolDefinition.fromJson(entry);
            } catch (Exception e) {
                throw new IOException("基线中工具 '" + Sanitizer.forReport(name, 80) + "' 的定义非法：" + e.getMessage(), e);
            }
            String recomputed = ToolFingerprint.of(tool);
            if (!recomputed.equals(fingerprint)) {
                throw new IOException("基线中工具 '" + Sanitizer.forReport(name, 80)
                        + "' 的定义与记录的 fingerprint 不一致（记录为 "
                        + ToolFingerprint.shortOf(fingerprint) + "，按定义重算为 "
                        + ToolFingerprint.shortOf(recomputed) + "）——基线可能被手工篡改或损坏。");
            }
            tools.add(new ToolEntry(tool, fingerprint));
            definitions.add(tool);
        }

        String surfaceFingerprint = root.path("surfaceFingerprint").asText("");
        String expectedSurfaceFp = ToolFingerprint.ofSurface(definitions);
        if (surfaceFingerprint.isBlank() || !expectedSurfaceFp.equals(surfaceFingerprint)) {
            throw new IOException("基线的 surfaceFingerprint 与工具列表重算结果不一致（记录为 "
                    + ToolFingerprint.shortOf(surfaceFingerprint) + "，重算为 "
                    + ToolFingerprint.shortOf(expectedSurfaceFp) + "）——基线内容不自洽。");
        }

        List<AcceptedChange> accepted = new ArrayList<>();
        if (root.has("acceptedChanges") && !root.path("acceptedChanges").isNull()) {
            JsonNode acceptedNode = root.path("acceptedChanges");
            if (!acceptedNode.isArray()) {
                throw new IOException("基线 acceptedChanges 字段不是数组。");
            }
            for (JsonNode node : acceptedNode) {
                if (!node.isObject()) {
                    throw new IOException("基线 acceptedChanges 中存在非对象条目。");
                }
                String id = requiredText(node, "id");
                String toolName = requiredText(node, "tool");
                String digest = requiredText(node, "digest");
                if (id.isBlank() || toolName.isBlank() || digest.isBlank()) {
                    throw new IOException("基线 acceptedChanges 条目缺少 id / tool / digest 字段。");
                }
                String approvalTarget = requiredText(node, "targetId");
                String beforeFp = requiredText(node, "beforeFingerprint");
                String afterFp = requiredText(node, "afterFingerprint");
                if (!beforeFp.matches("[0-9a-f]{64}") || !afterFp.matches("[0-9a-f]{64}")
                        || !digest.matches("[0-9a-f]{32}")) throw new IOException("基线审批指纹格式非法");
                accepted.add(new AcceptedChange(id, toolName, digest, approvalTarget, beforeFp, afterFp));
            }
        }
        return new Baseline(version, schemaVersion,
                requiredText(root, "server"),
                surfaceFingerprint,
                requiredText(root, "generatedAt"),
                tools, accepted, requiredText(root, "targetId"));
    }

    private static String requiredText(JsonNode root, String key) throws IOException {
        if (!root.path(key).isTextual() || root.path(key).textValue().isBlank()) {
            throw new IOException("基线 " + key + " 必须为非空字符串");
        }
        return root.get(key).textValue();
    }

    /**
     * 除 {@code generatedAt} 外，两份基线是否描述同一个工具面。
     */
    public boolean sameContentAs(Baseline other) {
        if (version != other.version
                || schemaVersion != other.schemaVersion
                || !java.util.Objects.equals(targetId, other.targetId)
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

    /**
     * F08 修正：同目录写临时文件 → 回读校验完整性 → 原子替换目标文件。
     */
    public void write(Path file) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", version);
        root.put("schemaVersion", schemaVersion);
        root.put("_comment", "MCP 工具面基线。请提交进版本库：工具定义变化应当出现在 diff 与评审中。"
                + "保存已采集定义的原文；指纹单独规范化；审批必须绑定已审阅的前后快照。");
        root.put("server", serverName);
        root.put("targetId", targetId);
        root.put("surfaceFingerprint", surfaceFingerprint);
        root.put("generatedAt", generatedAt);

        ArrayNode toolsNode = root.putArray("tools");
        for (ToolEntry entry : tools) {
            ObjectNode node = entry.tool().toRawJson();
            node.put("fingerprint", entry.fingerprint());
            toolsNode.add(node);
        }

        ArrayNode acceptedNode = root.putArray("acceptedChanges");
        for (AcceptedChange change : acceptedChanges) {
            ObjectNode node = acceptedNode.addObject();
            node.put("id", change.id());
            node.put("tool", change.toolName());
            node.put("digest", change.digest());
            node.put("targetId", change.targetId());
            node.put("beforeFingerprint", change.beforeFingerprint());
            node.put("afterFingerprint", change.afterFingerprint());
        }

        String serialized = MAPPER.writer(prettyPrinter()).writeValueAsString(root);
        AtomicFiles.write(file, serialized, temp -> {
            Baseline verified = read(temp);
            if (!this.sameContentAs(verified)) {
                throw new IOException("基线写入后回读校验不一致");
            }
        });
    }

    /** Compare and replace while coordinating writers using this tool. */
    public void writeExpected(Path file, Baseline expected) throws IOException {
        Path target = file.toAbsolutePath().normalize();
        Files.createDirectories(target.getParent());
        Path lockPath = target.resolveSibling(target.getFileName() + ".write-lock");
        try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            try (var lock = channel.tryLock()) {
                if (lock == null) throw new IOException("另一进程正在批准这份基线，请重新扫描");
                if (expected != null && !expected.equals(read(target))) throw new IOException("基线在审阅后已改变；未写回，请重新扫描");
                write(target);
            }
        } catch (OverlappingFileLockException e) {
            throw new IOException("另一进程正在批准这份基线，请重新扫描", e);
        }
    }

    static com.fasterxml.jackson.core.util.DefaultPrettyPrinter prettyPrinter() {
        com.fasterxml.jackson.core.util.DefaultPrettyPrinter printer =
                new com.fasterxml.jackson.core.util.DefaultPrettyPrinter();
        printer.indentArraysWith(com.fasterxml.jackson.core.util.DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
        return printer;
    }

    // ---------- 对比 ----------

    /**
     * 与当前工具面比较，得出<b>带类型的变更集</b>。
     */
    public SurfaceDiff diffAgainst(ToolSurface current) {
        Map<String, List<ToolEntry>> before = group(tools, entry -> entry.tool().name());
        Map<String, List<ToolDefinition>> after = group(current.sorted(), ToolDefinition::name);

        List<Change> changes = new ArrayList<>();
        List<PathChange> paths = new ArrayList<>();
        for (Map.Entry<String, List<ToolDefinition>> entry : after.entrySet()) {
            List<ToolEntry> previous = before.get(entry.getKey());
            for (int i = 0; i < entry.getValue().size(); i++) {
                ToolDefinition now = entry.getValue().get(i);
                if (previous == null || i >= previous.size()) {
                    paths.addAll(PathChange.between(entry.getKey(), i, null, now.toJson()));
                    changes.add(new Change("TOOL_ADDED", entry.getKey(), i, ChangeSeverity.DANGEROUS,
                            "新增工具", ToolFingerprint.of(now).substring(0, 16)).at(""));
                    continue;
                }
                ToolDefinition was = previous.get(i).tool();
                if (!ToolFingerprint.of(now).equals(previous.get(i).fingerprint())) {
                    List<PathChange> toolPaths = PathChange.between(entry.getKey(), i, was.toJson(), now.toJson());
                    paths.addAll(toolPaths);
                    List<Change> graded = SchemaDiff.between(was, now, i, toolPaths);
                    if (graded.isEmpty()) {
                        graded = List.of(new Change("UNGRADED_SCHEMA_CHANGE", entry.getKey(), i,
                                ChangeSeverity.DANGEROUS,
                                "schema 变了但分级器认不出改了哪一处（折叠、嵌套或本工具尚未覆盖的"
                                        + "关键字）。按最保守处理，请人工核对后 --accept-changes",
                                ToolFingerprint.of(now).substring(0, 16)));
                    }
                    changes.addAll(graded);
                }
            }
        }
        for (Map.Entry<String, List<ToolEntry>> entry : before.entrySet()) {
            List<ToolDefinition> currentTools = after.get(entry.getKey());
            int currentSize = currentTools == null ? 0 : currentTools.size();
            for (int i = currentSize; i < entry.getValue().size(); i++) {
                paths.addAll(PathChange.between(entry.getKey(), i, entry.getValue().get(i).tool().toJson(), null));
                changes.add(new Change("TOOL_REMOVED", entry.getKey(), i, ChangeSeverity.BREAKING,
                        "工具被移除", entry.getValue().get(i).fingerprint().substring(0, 16)).at(""));
            }
        }
        java.util.Set<String> applicable = new java.util.LinkedHashSet<>();
        for (AcceptedChange change : acceptedChanges) {
            if (targetId.equals(change.targetId()) && surfaceFingerprint.equals(change.beforeFingerprint())
                    && current.fingerprint().equals(change.afterFingerprint())) applicable.add(change.digest());
        }
        return new SurfaceDiff(changes, applicable, paths);
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
