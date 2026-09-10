package io.github.xiaoxusop.mcpsentinel;

import java.util.Locale;

/**
 * 一条工具面变更的严重级别。
 *
 * <p><b>判据与所有契约 diff 工具是反的</b>，这是 MCP 特有的，不是笔误。
 * oasdiff / buf breaking / graphql-inspector 的判据是"**请求收窄、响应放宽**会破坏客户端"，
 * 所以它们把"加了可选参数"判为兼容、把"描述改了"判为 {@code info}——
 * Cisco 的 mcpcontract 规则文件里逐字写着
 * {@code rationale: "Descriptions are informational only and don't affect functionality"}。
 *
 * <p>那对 OpenAPI 文档是对的，对 MCP 是**灾难性的**：MCP 里工具描述就是投放给模型的指令面，
 * 就是投毒本体；而模型按 schema 生成调用，**schema 扩大可传内容正是注入指令要利用的自由度**。
 *
 * <p>所以这里的判据翻过来：**任何扩大可传内容、或降低声明风险的变更都是危险的**。
 */
public enum ChangeSeverity {

    /** 记一笔就够了：标题改动、注解微调这类纯信息性的变化 */
    INFO,

    /** 会破坏调用方：加必填参数、删参数、收窄取值域。不是攻击，但调用方会挂 */
    BREAKING,

    /**
     * 扩大攻击面或降低声明风险：描述被改写、schema 放宽、{@code destructiveHint} 被翻成 false。
     *
     * <p>rug pull 的典型形态就落在这一档——先发布人畜无害的定义取得信任，再把描述或
     * 约束改成有权限的那版。
     */
    DANGEROUS;

    /** 是否达到给定级别（级别越高越严重） */
    public boolean atLeast(ChangeSeverity level) {
        return ordinal() >= level.ordinal();
    }

    /** 解析命令行给的级别名；不认识时抛异常而不是静默退回默认值 */
    public static ChangeSeverity parse(String name) {
        try {
            return valueOf(name.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("未知的变更级别 '" + name + "'（可用：INFO / BREAKING / DANGEROUS）");
        }
    }

    /** 供报告使用的紧凑标签 */
    public String label() {
        return switch (this) {
            case INFO -> "信息";
            case BREAKING -> "破坏兼容";
            case DANGEROUS -> "危险";
        };
    }
}
