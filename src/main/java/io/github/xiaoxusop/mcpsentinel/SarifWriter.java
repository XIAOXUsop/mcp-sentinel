package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 把扫描结果输出为 SARIF 2.1.0。
 *
 * <p>为什么值得单独做：SARIF 是代码扫描结果的事实标准格式，
 * GitHub Code Scanning、GitLab、Azure DevOps 都能直接读。有了它，
 * 发现会以**行内注解**的形式出现在 PR 上，而不是躺在 CI 日志里等人去翻——
 * 安全工具的价值很大程度上取决于"结果有没有被看见"。
 *
 * <p>工具面的"位置"用 {@code mcp://<server>/<tool>} 表示：MCP 工具不是文件，
 * 但 SARIF 需要一个稳定的定位符，URI 形式既唯一又能自解释。
 */
public final class SarifWriter {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

    private SarifWriter() {
    }

    public static String render(ScanReport report) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("$schema", SCHEMA);
        root.put("version", "2.1.0");

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "mcp-sentinel");
        driver.put("informationUri", "https://github.com/XIAOXUsop/mcp-sentinel");
        driver.put("version", "0.1.0");

        // rules 段声明规则元数据，results 只引用 id —— SARIF 消费方据此做分类与抑制
        ArrayNode rules = driver.putArray("rules");
        Map<String, Finding.Severity> declared = new LinkedHashMap<>();
        for (Finding finding : report.sortedFindings()) {
            declared.putIfAbsent(finding.ruleId(), finding.severity());
        }
        declared.forEach((ruleId, severity) -> {
            ObjectNode rule = rules.addObject();
            rule.put("id", ruleId);
            rule.put("name", ruleId);
            ObjectNode shortDescription = rule.putObject("shortDescription");
            shortDescription.put("text", ruleId);
            ObjectNode defaultConfig = rule.putObject("defaultConfiguration");
            defaultConfig.put("level", level(severity));
        });

        ArrayNode results = run.putArray("results");
        for (Finding finding : report.sortedFindings()) {
            ObjectNode result = results.addObject();
            result.put("ruleId", finding.ruleId());
            result.put("level", level(finding.severity()));
            result.putObject("message").put("text", finding.message()
                    + (finding.evidence().isBlank() ? "" : " — 证据: " + finding.evidence()));

            ObjectNode location = result.putArray("locations").addObject()
                    .putObject("physicalLocation");
            location.putObject("artifactLocation")
                    .put("uri", "mcp://" + report.serverName() + "/" + finding.toolName());
            ObjectNode properties = result.putObject("properties");
            properties.put("tool", finding.toolName());
            properties.put("surfaceFingerprint", report.shortFingerprint());
        }

        // 基线漂移本身也是一条结果：它不是"某个工具有风险"，而是"工具面变了"
        if (report.diff() != null && !report.diff().isClean()) {
            ObjectNode drift = results.addObject();
            drift.put("ruleId", "TOOL_SURFACE_DRIFT");
            drift.put("level", "error");
            drift.putObject("message").put("text", report.diff().summary());
            drift.putArray("locations").addObject().putObject("physicalLocation")
                    .putObject("artifactLocation")
                    .put("uri", "mcp://" + report.serverName());
        }

        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            throw new IllegalStateException("SARIF 序列化失败", e);
        }
    }

    public static void write(ScanReport report, Path file) throws IOException {
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        Files.writeString(file, render(report), StandardCharsets.UTF_8);
    }

    /** SARIF 的 level 词表与内部严重级别不同，需要映射 */
    private static String level(Finding.Severity severity) {
        return switch (severity) {
            case HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW -> "note";
        };
    }
}
