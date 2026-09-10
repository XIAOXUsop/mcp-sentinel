package io.github.xiaoxusop.mcpsentinel;

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
                         SurfaceDiff diff) {

    public ScanReport {
        findings = List.copyOf(findings);
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

    public String shortFingerprint() {
        return ToolFingerprint.shortOf(surfaceFingerprint);
    }

    /** 人读报告 */
    public String render() {
        StringBuilder sb = new StringBuilder();
        sb.append("MCP 工具面扫描\n");
        sb.append("  服务器      : ").append(serverName).append('\n');
        sb.append("  工具数      : ").append(toolCount).append('\n');
        sb.append("  工具面指纹  : ").append(shortFingerprint()).append('\n');
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
                    sb.append("      证据: ").append(finding.evidence()).append('\n');
                }
            }
        } else {
            sb.append("\n未发现风险项。\n");
        }
        return sb.toString();
    }
}
