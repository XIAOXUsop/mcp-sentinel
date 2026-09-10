package io.github.xiaoxusop.mcpsentinel;

import java.util.List;

/**
 * 当前工具面与基线的差异。
 *
 * <p>三类差异的安全含义不同，因此分开报告：
 * <ul>
 *   <li><b>新增</b>——可能是正常的版本迭代，也可能是影子工具</li>
 *   <li><b>修改</b>——最危险的一类：名字没变，但描述或 schema 变了。rug pull 就走这条路</li>
 *   <li><b>删除</b>——通常无害，但若是被替换成了同名不同源的实现，会表现为"删除 + 新增"</li>
 * </ul>
 *
 * <p>「修改」携带**改动前后的完整定义**，而不只是一个"变了"的结论。这是刻意的：
 * 只有拿到两边才能说出"改的是描述还是必填约束"——而这两者的安全含义正好相反。
 */
public record SurfaceDiff(List<String> added,
                          List<String> removed,
                          List<ModifiedTool> modified) {

    /**
     * @param occurrence 同名工具中的出现序号。重名工具按序号逐个配对，
     *                   否则其中一个被改写会被另一个覆盖掉
     */
    public record ModifiedTool(String name, int occurrence,
                               ToolDefinition before, ToolDefinition after) {
    }

    public SurfaceDiff {
        added = List.copyOf(added);
        removed = List.copyOf(removed);
        modified = List.copyOf(modified);
    }

    public boolean isClean() {
        return added.isEmpty() && removed.isEmpty() && modified.isEmpty();
    }

    public int totalChanges() {
        return added.size() + removed.size() + modified.size();
    }

    /** 人读摘要 */
    public String summary() {
        if (isClean()) {
            return "工具面与基线一致，无变化";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("工具面相对基线有 ").append(totalChanges()).append(" 处变化：");
        if (!added.isEmpty()) {
            sb.append("\n  新增 ").append(added.size()).append(" 个：").append(added);
        }
        if (!modified.isEmpty()) {
            sb.append("\n  修改 ").append(modified.size()).append(" 个：").append(modifiedNames())
              .append("  ← 定义被改写但名字未变，rug pull 的典型形态");
        }
        if (!removed.isEmpty()) {
            sb.append("\n  删除 ").append(removed.size()).append(" 个：").append(removed);
        }
        return sb.toString();
    }

    /** 被修改工具的名字（重名时带上序号，避免看不出来是哪一个） */
    public List<String> modifiedNames() {
        return modified.stream().map(SurfaceDiff::describe).toList();
    }

    static String describe(ModifiedTool change) {
        long sameName = change.occurrence();
        return sameName == 0 ? change.name() : change.name() + "#" + (sameName + 1);
    }
}
