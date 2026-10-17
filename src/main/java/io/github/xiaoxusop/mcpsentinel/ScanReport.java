package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Comparator;
import java.util.List;

/**
 * 一次扫描的完整结论：工具面概览 + 风险发现 + 与基线的差异。
 *
 * <p>三部分缺一不可：只看风险规则，发现不了"定义被悄悄改了"；
 * 只看基线差异，发现不了"第一次拉下来就带着注入指令"。
 */
public record ScanReport(String serverName,
                         String surfaceFingerprint,
                         int toolCount,
                         List<Finding> findings,
                         SurfaceDiff diff,
                         String baselineFingerprint,
                         String targetId,
                         List<ToolEvidence> tools,
                         List<ScanError> errors) {

    public static final int REPORT_VERSION = 2;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public ScanReport {
        findings = List.copyOf(findings);
        tools = List.copyOf(tools);
        errors = List.copyOf(errors);
    }

    public record ToolEvidence(String name, int occurrence, String fingerprint) { }

    public ScanReport(String serverName, String surfaceFingerprint, int toolCount, List<Finding> findings,
                      SurfaceDiff diff, String baselineFingerprint, String targetId) {
        this(serverName, surfaceFingerprint, toolCount, findings, diff, baselineFingerprint, targetId, List.of(), List.of());
    }

    public static ScanReport of(ToolSurface surface, List<Finding> findings, SurfaceDiff diff,
                                 String baselineFingerprint, String targetId, boolean fingerprintsAvailable) {
        var occurrences = new java.util.HashMap<String, Integer>();
        List<ToolEvidence> tools = surface.sorted().stream().map(tool -> new ToolEvidence(tool.name(),
                occurrences.merge(tool.name(), 1, Integer::sum) - 1,
                fingerprintsAvailable ? ToolFingerprint.of(tool) : "")).toList();
        return new ScanReport(surface.serverName(), fingerprintsAvailable ? surface.fingerprint() : "", surface.tools().size(),
                findings, diff, baselineFingerprint, targetId, tools, List.of());
    }

    public ScanReport withErrors(List<ScanError> failures) {
        return new ScanReport(serverName, surfaceFingerprint, toolCount, findings, diff, baselineFingerprint, targetId, tools, failures);
    }

    public ScanReport(String serverName, String surfaceFingerprint, int toolCount,
                      List<Finding> findings, SurfaceDiff diff) {
        this(serverName, surfaceFingerprint, toolCount, findings, diff, "", "server:" + serverName);
    }

    /** 按严重级别排序（HIGH 在前），同级按工具名——保证输出稳定 */
    public List<Finding> sortedFindings() {
        return findings.stream()
                .sorted(Comparator.comparing((Finding f) -> f.severity().ordinal())
                        .thenComparing(Finding::toolName)
                        .thenComparing(Finding::ruleId))
                .toList();
    }

    public long countOf(Finding.Severity severity) {
        return findings.stream().filter(f -> f.severity() == severity).count();
    }

    public boolean hasAtLeast(Finding.Severity severity) {
        return findings.stream().anyMatch(f -> f.severity().ordinal() <= severity.ordinal());
    }

    /**
     * 本次扫描中<b>实际出现的</b>最高风险级别；没有发现时返回 {@code null}。
     */
    public Finding.Severity highestSeverity() {
        return findings.stream()
                .map(Finding::severity)
                .min(Comparator.comparingInt(Finding.Severity::ordinal))
                .orElse(null);
    }

    public String shortFingerprint() {
        return ToolFingerprint.shortOf(surfaceFingerprint);
    }

    /**
     * 人读报告。
     */
    public String render() {
        StringBuilder sb = new StringBuilder();
        sb.append("MCP 工具面扫描\n");
        sb.append("  服务器      : ").append(Sanitizer.forReport(serverName, 120)).append('\n');
        sb.append("  工具数      : ").append(toolCount).append('\n');
        sb.append("  工具面指纹  : ").append(surfaceFingerprint).append('\n');
        if (!baselineFingerprint.isBlank()) sb.append("  基线指纹    : ").append(baselineFingerprint).append('\n');
        sb.append("  风险        : HIGH=").append(countOf(Finding.Severity.HIGH))
          .append(" MEDIUM=").append(countOf(Finding.Severity.MEDIUM))
          .append(" LOW=").append(countOf(Finding.Severity.LOW)).append('\n');

        if (diff != null) {
            sb.append('\n').append(diff.summary()).append('\n');
        }
        if (!findings.isEmpty()) {
            sb.append("\n风险明细：\n");
            for (Finding finding : sortedFindings()) {
                sb.append("  ").append(finding.format()).append('\n');
                if (!finding.evidence().isBlank()) {
                    sb.append("      证据: ").append(Sanitizer.forReport(finding.evidence(), 160)).append('\n');
                }
            }
        } else {
            sb.append("\n未发现风险项。\n");
        }
        return sb.toString();
    }

    /**
     * 版本化机器可读 JSON 报告（W06）。
     */
    public String renderJson(Finding.Severity failOn, ChangeSeverity failOnChange,
                             int exitCode, String errorCategory) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("reportVersion", REPORT_VERSION);
        root.put("toolVersion", Version.value());
        root.put("schemaVersion", SchemaCanonicalizer.VERSION);
        root.put("server", serverName);
        root.put("surfaceFingerprint", surfaceFingerprint);
        root.put("baselineFingerprint", baselineFingerprint);
        root.put("targetId", targetId);
        root.put("fingerprintsAvailable", !surfaceFingerprint.isBlank());
        root.put("collectionStatus", "COMPLETE");
        root.put("toolCount", toolCount);
        root.put("status", exitCode == 0 ? "PASS" : "FAIL");
        root.put("exitCode", exitCode);
        root.put("errorCategory", errorCategory == null ? "NONE" : errorCategory);

        var toolNodes = root.putArray("tools");
        for (ToolEvidence tool : tools) toolNodes.addObject().put("name", tool.name())
                .put("occurrence", tool.occurrence()).put("fingerprint", tool.fingerprint());
        var errorNodes = root.putArray("errors");
        for (ScanError error : errors) errorNodes.addObject().put("category", error.category())
                .put("phase", error.phase()).put("message", error.message());

        ObjectNode thresholds = root.putObject("thresholds");
        thresholds.put("failOnRisk", failOn.name());
        thresholds.put("failOnChange", failOnChange.name());

        ObjectNode counts = root.putObject("riskCounts");
        counts.put("HIGH", countOf(Finding.Severity.HIGH));
        counts.put("MEDIUM", countOf(Finding.Severity.MEDIUM));
        counts.put("LOW", countOf(Finding.Severity.LOW));

        ArrayNode findingsNode = root.putArray("findings");
        for (Finding finding : sortedFindings()) {
            ObjectNode item = findingsNode.addObject();
            item.put("ruleId", finding.ruleId());
            item.put("severity", finding.severity().name());
            item.put("tool", finding.toolName());
            item.put("message", finding.message());
            item.put("evidence", finding.evidence());
        }

        if (diff == null) {
            root.putNull("diff");
        } else {
            ObjectNode diffNode = root.putObject("diff");
            List<Change> blocking = diff.blocking(failOnChange);
            diffNode.put("clean", diff.isClean());
            diffNode.put("totalChanges", diff.totalChanges());
            diffNode.put("blockingChanges", blocking.size());
            var pathNodes = diffNode.putArray("paths");
            for (PathChange change : diff.paths()) {
                var item = pathNodes.addObject();
                item.put("tool", change.toolName()).put("occurrence", change.occurrence()).put("path", change.path());
                item.put("beforePresent", change.before() != null).put("afterPresent", change.after() != null);
                item.set("before", change.before()); item.set("after", change.after());
            }
            ArrayNode changesNode = diffNode.putArray("changes");
            for (Change change : diff.sorted()) {
                ObjectNode item = changesNode.addObject();
                item.put("id", change.id());
                item.put("tool", change.toolName());
                item.put("occurrence", change.occurrence());
                item.put("severity", change.severity().name());
                item.put("approved", diff.isApproved(change));
                item.put("detail", change.detail());
                item.put("digest", change.digest());
                var claimed = item.putArray("paths");
                change.paths().forEach(claimed::add);
            }
        }
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            throw new IllegalStateException("JSON 报告序列化失败", e);
        }
    }
}
