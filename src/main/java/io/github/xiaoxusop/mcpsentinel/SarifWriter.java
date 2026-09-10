package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 把扫描结果输出为 SARIF 2.1.0。
 *
 * <p>为什么值得单独做：SARIF 是代码扫描结果的事实标准格式，GitHub Code Scanning
 * 能直接读。有了它，发现会以**行内注解**的形式出现在 PR 上，而不是躺在 CI 日志里等人去翻。
 *
 * <p><b>但"能显示"是有前提的</b>：GitHub 官方校验器的规则 GH1005
 * （{@code LocationsMustBeRelativeUrisOrFilePaths}）只显示位置为**相对 URI**
 * 或 {@code file:} 方案绝对 URI 的结果。旧版输出 {@code mcp://<server>/<tool>}——
 * 绝对 URI 但方案不是 file，所以那些结果**根本不会显示**，
 * 而 README 却承诺了行内注解。现在改为指向仓库内真实存在的文件：
 * 有基线时指向基线文件、并精确到该工具在里面的行号，否则指向配置文件。
 */
public final class SarifWriter {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    private static final String HELP_BASE = "https://github.com/XIAOXUsop/mcp-sentinel#";

    /** 规则 id → 一句话说明。SARIF 消费方拿它做分类，写 id 本身对人没用 */
    private static final Map<String, String> RULE_SUMMARY = Map.ofEntries(
            Map.entry("HIDDEN_INSTRUCTION", "工具定义中含面向模型的指令性措辞（OWASP MCP03 tool poisoning）"),
            Map.entry("INVISIBLE_CHARACTERS", "定义中含零宽或双向控制字符"),
            Map.entry("ENCODED_PAYLOAD", "定义中含超长 base64 串，可能是被编码的隐藏指令"),
            Map.entry("SCHEMA_NO_PARAMETERS", "声明为 object 却没有任何属性"),
            Map.entry("SCHEMA_OPEN_OBJECT", "schema 允许 additionalProperties"),
            Map.entry("SCHEMA_NO_REQUIRED", "参数很多却没有任何必填约束"),
            Map.entry("SCHEMA_UNCONSTRAINED_STRING", "字符串参数没有任何取值约束"),
            Map.entry("DANGEROUS_PARAMETER", "参数名指向执行或访问面"),
            Map.entry("DESCRIPTION_SCHEMA_MISMATCH", "描述自称只读，schema 却含写入语义参数"),
            Map.entry("TOOL_SHADOWING", "与既有工具名称相近且描述雷同"),
            Map.entry("DUPLICATE_TOOL_NAME", "工具名重复，以名字为键的存储会互相覆盖"),
            Map.entry("UNSAFE_SERVER_NAME", "服务器名不符合规范字符集"),
            Map.entry("UNSAFE_TOOL_NAME", "工具名不符合 MCP 规范的字符集"),
            Map.entry("TOOL_ADDED", "新增工具（rug pull 最常见的形态）"),
            Map.entry("TOOL_REMOVED", "工具被移除"),
            Map.entry("DESCRIPTION_CHANGED", "工具描述被改写（描述即指令面）"),
            Map.entry("SCHEMA_OPENED", "schema 放宽：additionalProperties 变为打开"),
            Map.entry("PARAM_ADDED_OPTIONAL", "新增可选参数（扩大可传内容）"),
            Map.entry("PARAM_ADDED_REQUIRED", "新增必填参数（破坏调用方）"),
            Map.entry("PARAM_REMOVED", "参数被移除"),
            Map.entry("PARAM_CONSTRAINT_REMOVED", "参数约束被移除"),
            Map.entry("PARAM_CONSTRAINT_ADDED", "参数新增约束"),
            Map.entry("PARAM_ENUM_WIDENED", "参数取值域变宽"),
            Map.entry("PARAM_ENUM_NARROWED", "参数取值域变窄"),
            Map.entry("REQUIRED_ADDED", "参数变为必填"),
            Map.entry("REQUIRED_REMOVED", "参数不再必填"),
            Map.entry("ANNOTATION_DESTRUCTIVE_FLIPPED", "destructiveHint 被翻转"),
            Map.entry("ANNOTATION_READONLY_FLIPPED", "readOnlyHint 被翻转"),
            Map.entry("OUTPUT_SCHEMA_CHANGED", "出参 schema 被改写"));

    private SarifWriter() {
    }

    /**
     * 结果该定位到哪里。
     *
     * @param uri       仓库内的相对路径——GitHub 只会显示这种位置
     * @param toolLines 工具名（{@code 名字#序号}）→ 它在源文件里的行号
     */
    public record Source(String uri, Map<String, Integer> toolLines) {

        public Source {
            toolLines = Map.copyOf(toolLines);
        }

        public static Source of(String uri) {
            return new Source(uri, Map.of());
        }

        /** 有基线就用基线（能精确到行），否则退回配置文件（只能指到第 1 行） */
        public static Source fromFiles(Path configFile, Path baselineFile) throws IOException {
            Path chosen = Files.isRegularFile(baselineFile) ? baselineFile : configFile;
            Map<String, Integer> lines = Files.isRegularFile(baselineFile)
                    ? scanToolLines(baselineFile) : Map.of();
            return new Source(toRepoRelativeUri(chosen), lines);
        }

        public int lineOf(String toolName, int occurrence) {
            return toolLines.getOrDefault(toolName + "#" + occurrence, 1);
        }
    }

    public static String render(ScanReport report) {
        return render(report, Source.of("mcp-sentinel.lock.json"));
    }

    public static String render(ScanReport report, Source source) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("$schema", SCHEMA);
        root.put("version", "2.1.0");

        ObjectNode run = root.putArray("runs").addObject();
        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "mcp-sentinel");
        driver.put("informationUri", "https://github.com/XIAOXUsop/mcp-sentinel");
        driver.put("version", "0.2.0");

        // 先把要用的规则 id 收集齐（含漂移产生的那些），再声明——否则会出现
        // results 引用了 rules 里没有的 id
        Map<String, String> declared = new LinkedHashMap<>();
        for (Finding finding : report.sortedFindings()) {
            declared.putIfAbsent(finding.ruleId(), sarifLevel(finding.severity()));
        }
        if (report.diff() != null) {
            for (Change change : report.diff().changes()) {
                declared.putIfAbsent(change.id(), sarifLevel(change.severity()));
            }
        }

        ArrayNode rules = driver.putArray("rules");
        Map<String, Integer> ruleIndex = new HashMap<>();
        declared.forEach((ruleId, level) -> {
            ruleIndex.put(ruleId, rules.size());
            ObjectNode rule = rules.addObject();
            rule.put("id", ruleId);
            rule.put("name", ruleId);
            rule.putObject("shortDescription").put("text", RULE_SUMMARY.getOrDefault(ruleId, ruleId));
            rule.putObject("fullDescription").put("text", RULE_SUMMARY.getOrDefault(ruleId, ruleId));
            rule.put("helpUri", HELP_BASE + ruleId);
            rule.putObject("defaultConfiguration").put("level", level);
            rule.putObject("properties").put("tags", "security").put("precision", "high");
        });

        ArrayNode results = run.putArray("results");
        for (Finding finding : report.sortedFindings()) {
            ObjectNode result = results.addObject();
            String ruleId = finding.ruleId();
            result.put("ruleId", ruleId);
            if (ruleIndex.containsKey(ruleId)) {
                result.put("ruleIndex", ruleIndex.get(ruleId));
            }
            result.put("level", sarifLevel(finding.severity()));
            result.putObject("message").put("text", Sanitizer.forSarifText(
                    finding.message() + (finding.evidence().isBlank()
                            ? "" : " — 证据: " + finding.evidence())));
            locate(result, source, finding.toolName(), 0, report, ruleId);
        }

        // 每个变更单独一条结果：调用方据此决定"改了什么、什么级别、要不要批准"
        if (report.diff() != null) {
            for (Change change : report.diff().changes()) {
                ObjectNode result = results.addObject();
                result.put("ruleId", change.id());
                if (ruleIndex.containsKey(change.id())) {
                    result.put("ruleIndex", ruleIndex.get(change.id()));
                }
                result.put("level", sarifLevel(change.severity()));
                result.putObject("message").put("text", Sanitizer.forSarifText(
                        "工具面变更（%s，%s）：%s".formatted(change.severity().label(),
                                report.diff().isApproved(change) ? "已批准" : "未批准",
                                change.detail())));
                locate(result, source, change.toolName(), change.occurrence(), report, change.id());
            }
        }

        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            throw new IllegalStateException("SARIF 序列化失败", e);
        }
    }

    /**
     * 给一条结果定位。
     *
     * <p>位置必须落在**仓库内真实存在的文件**上，否则 GitHub 不显示。
     * 工具名这些语义信息放进 {@code logicalLocations} 与 {@code properties}——
     * 它们不该挤占定位符。
     */
    private static void locate(ObjectNode result, Source source, String toolName, int occurrence,
                               ScanReport report, String ruleId) {
        ObjectNode physical = result.putArray("locations").addObject().putObject("physicalLocation");
        physical.putObject("artifactLocation").put("uri", source.uri());
        physical.putObject("region").put("startLine", source.lineOf(toolName, occurrence));

        ObjectNode logical = result.putArray("logicalLocations").addObject();
        logical.put("name", Sanitizer.forSarifText(
                occurrence == 0 ? toolName : toolName + "#" + (occurrence + 1)));
        logical.put("fullyQualifiedName", "mcp://" + Sanitizer.forUriSegment(report.serverName())
                + "/" + Sanitizer.forUriSegment(toolName));
        logical.put("kind", "resource");

        ObjectNode properties = result.putObject("properties");
        properties.put("server", Sanitizer.forSarifText(report.serverName()));
        properties.put("tool", Sanitizer.forSarifText(toolName));
        properties.put("surfaceFingerprint", report.shortFingerprint());

        // 自己算，不要让上传工具去读文件——文件读不到它就每次新建一条 alert 而非更新
        result.putObject("partialFingerprints")
                .put("mcp-sentinel/v1", fingerprint(ruleId, toolName, report.serverName()));
    }

    /** 同一条规则命中同一个工具 → 同一个指纹，这样重跑是更新 alert 而不是新增 */
    private static String fingerprint(String ruleId, String toolName, String serverName) {
        return ToolFingerprint.sha256(ruleId + " " + toolName + " " + serverName)
                .substring(0, 16);
    }

    public static void write(ScanReport report, Path file) throws IOException {
        write(report, Source.of(file.getFileName().toString()), file);
    }

    public static void write(ScanReport report, Source source, Path file) throws IOException {
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        Files.writeString(file, render(report, source), StandardCharsets.UTF_8);
    }

    /** SARIF 的 level 词表与内部严重级别不同，需要映射 */
    private static String sarifLevel(Finding.Severity severity) {
        return switch (severity) {
            case HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW -> "note";
        };
    }

    /**
     * 变更级别映射到 SARIF level。
     *
     * <p>只有 {@code DANGEROUS} 用 {@code error}：GitHub 默认把 {@code error} 显示为
     * 阻断性的注解，而"加了个必填参数"虽然会打断调用方，却不是安全问题。
     * 把两者都标成 error 会让真正的危险信号淹没在噪声里。
     */
    private static String sarifLevel(ChangeSeverity severity) {
        return switch (severity) {
            case DANGEROUS -> "error";
            case BREAKING -> "warning";
            case INFO -> "note";
        };
    }

    /**
     * 把路径变成 SARIF 要的定位符：优先**仓库内相对路径**（GitHub 只显示这种），
     * 文件在工作目录之外时退回 {@code file:} 方案的绝对 URI——官方规则 GH1005
     * 也接受这一种，而裸的绝对路径两种都不是。
     */
    private static String toRepoRelativeUri(Path path) {
        Path absolute = path.toAbsolutePath().normalize();
        Path base = Path.of("").toAbsolutePath().normalize();
        try {
            if (absolute.startsWith(base)) {
                return base.relativize(absolute).toString().replace('\\', '/');
            }
        } catch (IllegalArgumentException e) {
            // 跨盘符时 relativize 会抛，落到下面的 file: 分支
        }
        return "file:///" + absolute.toString().replace('\\', '/');
    }

    /**
     * 扫描基线文件，找出每个工具名所在的行号，供注解精确定位。
     *
     * <p>靠"进入 tools 数组、遇到 acceptedChanges 结束"来界定范围，
     * 而不是靠匹配方括号——数组与对象的缩进写法会随打印器变化，靠括号太脆。
     */
    private static Map<String, Integer> scanToolLines(Path baselineFile) throws IOException {
        Pattern nameLine = Pattern.compile("^\\s*\"name\"\\s*:\\s*\"(.*?)\"\\s*,?\\s*$");
        Map<String, Integer> lines = new LinkedHashMap<>();
        Map<String, Integer> seen = new HashMap<>();
        List<String> content = Files.readAllLines(baselineFile, StandardCharsets.UTF_8);
        boolean inTools = false;
        for (int i = 0; i < content.size(); i++) {
            String line = content.get(i);
            if (!inTools) {
                if (line.contains("\"tools\"") && line.contains("[")) {
                    inTools = true;
                    if (line.matches("^\\s*\"tools\"\\s*:\\s*\\[\\s*$")) {
                        continue;
                    }
                    // 首元素与 `[` 同行的写法：继续往下走，本行也参与匹配
                } else {
                    continue;
                }
            }
            if (line.contains("\"acceptedChanges\"")) {
                break;
            }
            Matcher matcher = nameLine.matcher(line);
            if (matcher.matches()) {
                String name = matcher.group(1);
                int occurrence = seen.merge(name, 1, Integer::sum) - 1;
                lines.putIfAbsent(name + "#" + occurrence, i + 1);
            }
        }
        return lines;
    }
}
