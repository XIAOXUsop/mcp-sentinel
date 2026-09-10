package io.github.xiaoxusop.mcpsentinel;

import java.util.Comparator;
import java.util.List;

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

    /** 工具名排序后的视图（保证报告与遍历顺序确定） */
    public List<ToolDefinition> sorted() {
        return tools.stream().sorted(Comparator.comparing(ToolDefinition::name)).toList();
    }

    public String fingerprint() {
        return ToolFingerprint.ofSurface(tools);
    }

    public String shortFingerprint() {
        return ToolFingerprint.shortOf(fingerprint());
    }
}
