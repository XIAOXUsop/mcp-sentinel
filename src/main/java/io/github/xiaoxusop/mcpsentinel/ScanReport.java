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

    /**
     * 本次扫描中**实际出现的**最高风险级别；没有发现时返回 {@code null}。
     *
     * <p>存在的理由：CI 注解曾经报的是**阻断阈值**而不是实际级别，
     * 于是一次 HIGH 的发现、配上 {@code --fail-on MEDIUM}，注解会说成
     * 「达到 MEDIUM 级别」——**低报**。对安全工具来说，注解与事实不符
     * 会让读的人按错误的严重度处理。
     *
     * <p>注意 {@link Finding.Severity} 的声明顺序是 {@code HIGH, MEDIUM, LOW}，
     * **ordinal 越小越严重**，所以这里取的是 {@code min} 而不是 {@code max}。
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
     *
     * <p>服务器名来自**被扫描的服务器**，是不可信输入。实测一个带换行的名字
     * 足以在报告里伪造出"工具面指纹"、"风险 HIGH=0" 这些行，还能注入
     * GitHub Actions 的 {@code ::notice::} 工作流命令。
     */
    public String render() {
        StringBuilder sb = new StringBuilder();
        sb.append("MCP 工具面扫描\n");
        sb.append("  服务器      : ").append(Sanitizer.forReport(serverName, 120)).append('\n');
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
                    // 证据直接引自服务器提供的定义，同样要消毒
                    sb.append("      证据: ").append(Sanitizer.forReport(finding.evidence(), 160)).append('\n');
                }
            }
        } else {
            sb.append("\n未发现风险项。\n");
        }
        return sb.toString();
    }
}
