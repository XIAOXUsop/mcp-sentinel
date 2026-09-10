package io.github.xiaoxusop.mcpsentinel;

import java.util.Map;

/**
 * 当前工具面与基线的差异。
 *
 * <p>三类差异的安全含义不同，因此分开报告而不合成一个"变了/没变"：
 * <ul>
 *   <li><b>新增</b>——可能是正常的版本迭代，也可能是影子工具（TOOL_SHADOWING 规则专门盯这个）</li>
 *   <li><b>修改</b>——最危险的一类：名字没变，但描述或 schema 变了。rug pull 就走这条路</li>
 *   <li><b>删除</b>——通常无害，但若是被替换成了同名不同源的实现，会表现为"删除 + 新增"</li>
 * </ul>
 */
public record SurfaceDiff(Map<String, String> added,
                          Map<String, String> removed,
                          Map<String, String> changed) {

    public boolean isClean() {
        return added.isEmpty() && removed.isEmpty() && changed.isEmpty();
    }

    public int totalChanges() {
        return added.size() + removed.size() + changed.size();
    }

    /** 人读摘要 */
    public String summary() {
        if (isClean()) {
            return "工具面与基线一致，无变化";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("工具面相对基线有 ").append(totalChanges()).append(" 处变化：");
        if (!added.isEmpty()) {
            sb.append("\n  新增 ").append(added.size()).append(" 个：").append(added.keySet());
        }
        if (!changed.isEmpty()) {
            sb.append("\n  修改 ").append(changed.size()).append(" 个：").append(changed.keySet())
              .append("  ← 定义被改写但名字未变，rug pull 的典型形态");
        }
        if (!removed.isEmpty()) {
            sb.append("\n  删除 ").append(removed.size()).append(" 个：").append(removed.keySet());
        }
        return sb.toString();
    }
}
