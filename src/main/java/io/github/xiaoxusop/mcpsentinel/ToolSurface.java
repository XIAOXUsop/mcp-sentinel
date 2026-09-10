package io.github.xiaoxusop.mcpsentinel;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 一个 MCP 服务器对外暴露的完整工具面。
 *
 * <p>指纹的对象是"整个面"而不只是单个工具——工具影子攻击正是靠**新增**一个
 * 与既有工具高度相似的定义来冒充它，只看单个工具是发现不了的。
 */
public record ToolSurface(String serverName, List<ToolDefinition> tools) {

    public ToolSurface {
        tools = List.copyOf(tools);
    }

    public static ToolSurface of(String serverName, List<ToolDefinition> tools) {
        return new ToolSurface(serverName, tools);
    }

    /**
     * 工具名排序后的视图（保证报告与遍历顺序确定）。
     *
     * <p>{@code sorted} 是**稳定**排序，同名工具的先后保持服务端给出的原始顺序——
     * 基线与当前面的配对依赖这一点。
     */
    public List<ToolDefinition> sorted() {
        return tools.stream().sorted(Comparator.comparing(ToolDefinition::name)).toList();
    }

    /**
     * 出现多次的工具名。
     *
     * <p>为什么必须单独报出来：任何以工具名为键的存储（包括本项目的旧版基线）
     * 遇到重名都会互相覆盖，于是**对其中一个的修改会被完全静默地吞掉**——
     * 攻击者只要把投毒工具命名成与既有工具同名，就永久免疫漂移检测。
     * MCP 规范只要求工具名在单个 server 内唯一（是 SHOULD 不是 MUST），
     * 并明确警告跨 server 聚合时会出现命名冲突，所以这不是畸形输入。
     */
    public List<String> duplicateNames() {
        Map<String, Integer> counts = new TreeMap<>();
        for (ToolDefinition tool : tools) {
            counts.merge(tool.name(), 1, Integer::sum);
        }
        return counts.entrySet().stream()
                .filter(entry -> entry.getValue() > 1)
                .map(Map.Entry::getKey)
                .toList();
    }

    public String fingerprint() {
        return ToolFingerprint.ofSurface(tools);
    }

    public String shortFingerprint() {
        return ToolFingerprint.shortOf(fingerprint());
    }
}
