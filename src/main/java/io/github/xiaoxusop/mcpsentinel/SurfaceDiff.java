package io.github.xiaoxusop.mcpsentinel;

import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * 当前工具面与基线的差异，是一组**带类型的变更**。
 *
 * <p>旧模型是「三个名字列表」，只能说出"哪些工具变了"，说不出"改的是什么"。
 * 现在每条变更都有自己的类型与严重级别，于是"加了一个可选参数"与"加了一个必填参数"
 * 不再长得一样——它们的处置正好相反。
 *
 * <p>{@code approvedDigests} 是基线里已批准的变更指纹集合。命中的变更仍然会被报告，
 * 但**不阻断 CI**：变更在首次出现时要人批准一次，之后每次运行都不必再批准。
 */
public record SurfaceDiff(List<Change> changes, Set<String> approvedDigests) {

    public SurfaceDiff {
        changes = List.copyOf(changes);
        approvedDigests = Set.copyOf(approvedDigests);
    }

    public SurfaceDiff(List<Change> changes) {
        this(changes, Set.of());
    }

    public boolean isClean() {
        return changes.isEmpty();
    }

    public int totalChanges() {
        return changes.size();
    }

    /** 该变更是否已被基线批准过 */
    public boolean isApproved(Change change) {
        return approvedDigests.contains(change.digest());
    }

    /** 未被批准、且达到给定级别的变更——这些才是要阻断 CI 的 */
    public List<Change> blocking(ChangeSeverity level) {
        return sorted().stream()
                .filter(change -> change.severity().atLeast(level) && !isApproved(change))
                .toList();
    }

    /** 按严重级别降序、同级按工具名排序——保证输出稳定 */
    public List<Change> sorted() {
        return changes.stream()
                .sorted(Comparator.comparing((Change c) -> c.severity().ordinal()).reversed()
                        .thenComparing(Change::toolName)
                        .thenComparing(Change::id))
                .toList();
    }

    public List<String> added() {
        return namesOf("TOOL_ADDED");
    }

    public List<String> removed() {
        return namesOf("TOOL_REMOVED");
    }

    private List<String> namesOf(String id) {
        return sorted().stream().filter(change -> change.id().equals(id))
                .map(Change::describe).toList();
    }

    /** 人读摘要：按级别分组，已批准的标出来 */
    public String summary() {
        if (isClean()) {
            return "工具面与基线一致，无变化";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("工具面相对基线有 ").append(totalChanges()).append(" 处变化：");
        for (Change change : sorted()) {
            sb.append("\n  ").append(change.format());
            if (isApproved(change)) {
                sb.append("  ← 已批准");
            }
        }
        return sb.toString();
    }
}
