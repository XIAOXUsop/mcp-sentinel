package io.github.xiaoxusop.mcpsentinel;

/**
 * 一条工具面变更。
 *
 * <p>与"指纹变了"的区别在于**说得出改了什么**：加了可选参数与加了必填参数在旧模型里
 * 都是"变了"，而前者扩大攻击面、后者破坏调用方——安全含义正好相反。
 *
 * @param id         变更类型标识（低基数，适合做指标标签与豁免名单的键）
 * @param toolName   涉及的工具
 * @param occurrence 同名工具中的出现序号；0 表示唯一名
 * @param severity   严重级别，判据见 {@link ChangeSeverity}
 * @param detail     这条变更的可读说明
 * @param afterDigest 变更后相关内容的摘要，**参与变更指纹的计算但不展示**
 */
public record Change(String id, String toolName, int occurrence,
                     ChangeSeverity severity, String detail, String afterDigest) {

    public Change {
        detail = detail == null ? "" : detail;
        afterDigest = afterDigest == null ? "" : afterDigest;
    }

    public static Change of(String id, ChangeSeverity severity, ToolDefinition tool, String detail) {
        return new Change(id, tool.name(), 0, severity, detail,
                ToolFingerprint.sha256(tool.canonicalForm()).substring(0, 16));
    }

    /** 报告里的工具标识；重名时带序号，否则看不出来是哪一个 */
    public String describe() {
        return occurrence == 0 ? toolName : toolName + "#" + (occurrence + 1);
    }

    /**
     * 变更指纹：用于**跨 commit 的审批继承**。
     *
     * <p>只由「变更类型 + 工具 + 具体内容 + **变更后的内容摘要**」算出来，
     * 不含行号、不含工具面指纹——因此在 commit A 批准过的变更，只要在 commit B 里
     * 仍然存在，就仍然是已批准状态，不需要因为"改了别的东西"而重新批准一遍。
     *
     * <p><b>为什么必须带上 afterDigest</b>：如果指纹只绑定"变更类型"，
     * 那么"描述 A→B 被批准"之后再 B→C 会**自动继承那次批准**——
     * 而"批准之后悄悄再改一次"恰好就是 rug pull 的形态。
     *
     * <p>不是新点子：oasdiff 的 {@code FINGERPRINT.md} 验证过这套做法，
     * 但在 MCP 工具面这个场景里还没有人做。
     */
    public String digest() {
        return ToolFingerprint
                .sha256(id + ":" + toolName + "#" + occurrence + ":" + detail + ":" + afterDigest)
                .substring(0, 32);
    }

    /** 一行报告 */
    public String format() {
        return "[%s] %s  %s  %s".formatted(severity, id, describe(), detail);
    }
}
