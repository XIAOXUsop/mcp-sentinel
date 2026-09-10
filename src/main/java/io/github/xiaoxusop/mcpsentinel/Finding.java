package io.github.xiaoxusop.mcpsentinel;

/**
 * 一条风险发现。
 *
 * @param ruleId    规则标识（低基数，适合做指标标签与豁免名单键）
 * @param severity  严重级别
 * @param toolName  命中的工具
 * @param message   人类可读说明：**为什么**这条有风险，而不只是"命中了规则"
 * @param evidence  证据片段（截断后的原文），便于人工复核
 */
public record Finding(String ruleId, Severity severity, String toolName, String message, String evidence) {

    private static final int EVIDENCE_LIMIT = 160;

    public Finding {
        evidence = evidence == null ? "" : evidence;
        if (evidence.length() > EVIDENCE_LIMIT) {
            evidence = evidence.substring(0, EVIDENCE_LIMIT) + "…";
        }
    }

    /** 严重级别。用于决定退出码：HIGH 阻断 CI，MEDIUM 只提示。 */
    public enum Severity {
        HIGH,
        MEDIUM,
        LOW
    }

    /** SARIF / 日志里的一行 */
    public String format() {
        return "[%s] %s  %s  %s".formatted(severity, ruleId, toolName, message);
    }
}
