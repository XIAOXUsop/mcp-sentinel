package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * 逐字段比较两份工具定义，产出**带类型的变更**。
 *
 * <p>旧模型只有"指纹相等 / 不等"，于是「加了可选参数」「改了描述」「加了必填参数」
 * 三者输出完全一样。而它们的处置完全不同：第一个扩大攻击面、第二个是投毒本体、
 * 第三个会打断所有调用方。
 *
 * <p>每条变更都带上**变更后内容的摘要**（{@link Change#afterDigest()}）。
 * 这是必需的：如果变更指纹只绑定"变更类型"，那么"描述 A→B 被批准"之后再 B→C
 * 会自动继承那次批准——而"批准之后悄悄再改一次"恰好就是 rug pull 的形态。
 */
final class SchemaDiff {

    /** 会被当作约束的关键字。它们的增删改都改变可传内容的自由度 */
    private static final List<String> CONSTRAINTS = List.of(
            "pattern", "format", "maxLength", "minLength", "maximum", "minimum", "multipleOf");

    private SchemaDiff() {
    }

    static List<Change> between(ToolDefinition before, ToolDefinition after, int occurrence) {
        List<Change> changes = new ArrayList<>();
        String name = after.name();

        String beforeDescription = SchemaCanonicalizer.normalizeText(before.description());
        String afterDescription = SchemaCanonicalizer.normalizeText(after.description());
        if (!beforeDescription.equals(afterDescription)) {
            changes.add(new Change("DESCRIPTION_CHANGED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "工具描述被改写（描述会进入模型上下文，是投毒的本体）",
                    shortHash(afterDescription)));
        }

        String beforeTitle = SchemaCanonicalizer.normalizeText(before.title());
        String afterTitle = SchemaCanonicalizer.normalizeText(after.title());
        if (!beforeTitle.equals(afterTitle)) {
            changes.add(new Change("TITLE_CHANGED", name, occurrence, ChangeSeverity.INFO,
                    "标题被改写", shortHash(afterTitle)));
        }

        JsonNode beforeOutput = SchemaCanonicalizer.canonicalize(before.outputSchema());
        JsonNode afterOutput = SchemaCanonicalizer.canonicalize(after.outputSchema());
        if (!beforeOutput.equals(afterOutput)) {
            changes.add(new Change("OUTPUT_SCHEMA_CHANGED", name, occurrence, ChangeSeverity.BREAKING,
                    "出参 schema 被改写（调用方依据它校验返回值）", shortHash(afterOutput.toString())));
        }

        annotate(before.annotations(), after.annotations(), name, occurrence, changes);
        inputSchema(before.inputSchema(), after.inputSchema(), name, occurrence, changes);
        return changes;
    }

    // ---------- 注解：声明的风险等级被改写 ----------

    /**
     * {@code destructiveHint} 与 {@code readOnlyHint} 是**客户端据此决定要不要自动放行**的声明。
     *
     * <p>把它们往"更安全"的方向翻（破坏性→非破坏性、非只读→只读）是危险方向：
     * 客户端会因此少一道确认，而实际行为并没有变安全。
     */
    private static void annotate(JsonNode before, JsonNode after, String name, int occurrence,
                                 List<Change> changes) {
        boolean beforeDestructive = before.path("destructiveHint").asBoolean(false);
        boolean afterDestructive = after.path("destructiveHint").asBoolean(false);
        if (beforeDestructive != afterDestructive) {
            changes.add(new Change("ANNOTATION_DESTRUCTIVE_FLIPPED", name, occurrence,
                    afterDestructive ? ChangeSeverity.INFO : ChangeSeverity.DANGEROUS,
                    "destructiveHint %s → %s".formatted(beforeDestructive, afterDestructive),
                    shortHash(before + "|" + after)));
        }

        boolean beforeReadOnly = before.path("readOnlyHint").asBoolean(false);
        boolean afterReadOnly = after.path("readOnlyHint").asBoolean(false);
        if (beforeReadOnly != afterReadOnly) {
            changes.add(new Change("ANNOTATION_READONLY_FLIPPED", name, occurrence,
                    afterReadOnly ? ChangeSeverity.DANGEROUS : ChangeSeverity.INFO,
                    "readOnlyHint %s → %s".formatted(beforeReadOnly, afterReadOnly),
                    shortHash(before + "|" + after)));
        }

        JsonNode canonicalBefore = SchemaCanonicalizer.canonicalize(before);
        JsonNode canonicalAfter = SchemaCanonicalizer.canonicalize(after);
        if (!canonicalBefore.equals(canonicalAfter) && beforeDestructive == afterDestructive
                && beforeReadOnly == afterReadOnly) {
            changes.add(new Change("ANNOTATION_CHANGED", name, occurrence, ChangeSeverity.INFO,
                    "注解被改写", shortHash(canonicalAfter.toString())));
        }
    }

    // ---------- 入参 schema ----------

    private static void inputSchema(JsonNode before, JsonNode after, String name, int occurrence,
                                    List<Change> changes) {
        JsonNode beforeProperties = before.path("properties");
        JsonNode afterProperties = after.path("properties");
        Set<String> beforeParams = fieldNames(beforeProperties);
        Set<String> afterParams = fieldNames(afterProperties);
        Set<String> beforeRequired = textSet(before.path("required"));
        Set<String> afterRequired = textSet(after.path("required"));

        for (String param : new TreeSet<>(difference(afterParams, beforeParams))) {
            boolean required = afterRequired.contains(param);
            changes.add(new Change(
                    required ? "PARAM_ADDED_REQUIRED" : "PARAM_ADDED_OPTIONAL", name, occurrence,
                    // 加必填打断调用方；加可选是**新增自由度**——模型可能被诱导去填它
                    required ? ChangeSeverity.BREAKING : ChangeSeverity.DANGEROUS,
                    "参数 %s %s".formatted(param, required ? "（必填）" : "（可选）"),
                    shortHash(afterProperties.path(param).toString())));
        }
        for (String param : new TreeSet<>(difference(beforeParams, afterParams))) {
            changes.add(new Change("PARAM_REMOVED", name, occurrence, ChangeSeverity.BREAKING,
                    "参数 %s 被移除".formatted(param), shortHash(param)));
        }
        for (String param : new TreeSet<>(intersection(beforeParams, afterParams))) {
            compareParameter(param, beforeProperties.path(param), afterProperties.path(param),
                    name, occurrence, changes);
        }

        // 「变为必填」只对**原本就存在**的参数说——新增的参数已经由 PARAM_ADDED_REQUIRED
        // 表达过一次了，再说一遍是冗余的告警，而冗余的告警会教人忽略告警
        for (String param : new TreeSet<>(difference(difference(afterRequired, beforeRequired),
                difference(afterParams, beforeParams)))) {
            changes.add(new Change("REQUIRED_ADDED", name, occurrence, ChangeSeverity.BREAKING,
                    "参数 %s 变为必填".formatted(param), shortHash(param)));
        }
        for (String param : new TreeSet<>(difference(difference(beforeRequired, afterRequired),
                difference(beforeParams, afterParams)))) {
            changes.add(new Change("REQUIRED_REMOVED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "参数 %s 不再必填（调用方可以省略它了）".formatted(param), shortHash(param)));
        }

        boolean beforeOpen = before.path("additionalProperties").asBoolean(false);
        boolean afterOpen = after.path("additionalProperties").asBoolean(false);
        if (!beforeOpen && afterOpen) {
            changes.add(new Change("SCHEMA_OPENED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "additionalProperties 由关闭变为打开：未声明的字段会被静默接受",
                    shortHash("open")));
        } else if (beforeOpen && !afterOpen) {
            changes.add(new Change("SCHEMA_CLOSED", name, occurrence, ChangeSeverity.BREAKING,
                    "additionalProperties 由打开变为关闭", shortHash("closed")));
        }
    }

    private static void compareParameter(String param, JsonNode before, JsonNode after,
                                         String name, int occurrence, List<Change> changes) {
        String beforeType = typeOf(before);
        String afterType = typeOf(after);
        if (!beforeType.equals(afterType)) {
            boolean widened = widens(beforeType, afterType);
            changes.add(new Change(widened ? "PARAM_TYPE_WIDENED" : "PARAM_TYPE_CHANGED",
                    name, occurrence, widened ? ChangeSeverity.DANGEROUS : ChangeSeverity.BREAKING,
                    "参数 %s 的类型 %s → %s".formatted(param, beforeType, afterType),
                    shortHash(afterType)));
        }

        Set<String> beforeEnum = enumValues(before);
        Set<String> afterEnum = enumValues(after);
        if (beforeEnum != null && afterEnum == null) {
            changes.add(new Change("PARAM_ENUM_REMOVED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "参数 %s 去掉了 enum 约束：取值域变成任意值".formatted(param), shortHash("none")));
        } else if (beforeEnum == null && afterEnum != null) {
            changes.add(new Change("PARAM_ENUM_ADDED", name, occurrence, ChangeSeverity.BREAKING,
                    "参数 %s 新增了 enum 约束".formatted(param), shortHash(afterEnum.toString())));
        } else if (beforeEnum != null) {
            if (afterEnum.containsAll(beforeEnum) && !afterEnum.equals(beforeEnum)) {
                changes.add(new Change("PARAM_ENUM_WIDENED", name, occurrence, ChangeSeverity.DANGEROUS,
                        "参数 %s 的取值域变宽：%s → %s".formatted(param, beforeEnum, afterEnum),
                        shortHash(afterEnum.toString())));
            } else if (beforeEnum.containsAll(afterEnum) && !afterEnum.equals(beforeEnum)) {
                changes.add(new Change("PARAM_ENUM_NARROWED", name, occurrence, ChangeSeverity.BREAKING,
                        "参数 %s 的取值域变窄：%s → %s".formatted(param, beforeEnum, afterEnum),
                        shortHash(afterEnum.toString())));
            } else if (!afterEnum.equals(beforeEnum)) {
                changes.add(new Change("PARAM_ENUM_CHANGED", name, occurrence, ChangeSeverity.BREAKING,
                        "参数 %s 的取值域改变：%s → %s".formatted(param, beforeEnum, afterEnum),
                        shortHash(afterEnum.toString())));
            }
        }

        for (String constraint : CONSTRAINTS) {
            JsonNode beforeValue = before.path(constraint);
            JsonNode afterValue = after.path(constraint);
            boolean beforeHas = !beforeValue.isMissingNode() && !beforeValue.isNull();
            boolean afterHas = !afterValue.isMissingNode() && !afterValue.isNull();
            if (beforeHas && !afterHas) {
                changes.add(new Change("PARAM_CONSTRAINT_REMOVED", name, occurrence, ChangeSeverity.DANGEROUS,
                        "参数 %s 去掉了 %s 约束".formatted(param, constraint), shortHash("none")));
            } else if (!beforeHas && afterHas) {
                changes.add(new Change("PARAM_CONSTRAINT_ADDED", name, occurrence, ChangeSeverity.BREAKING,
                        "参数 %s 新增 %s 约束".formatted(param, constraint),
                        shortHash(afterValue.toString())));
            } else if (beforeHas && !beforeValue.equals(afterValue)) {
                changes.add(new Change("PARAM_CONSTRAINT_CHANGED", name, occurrence, ChangeSeverity.BREAKING,
                        "参数 %s 的 %s 由 %s 改为 %s".formatted(param, constraint, beforeValue, afterValue),
                        shortHash(afterValue.toString())));
            }
        }

        String beforeDescription = SchemaCanonicalizer.normalizeText(before.path("description").asText(""));
        String afterDescription = SchemaCanonicalizer.normalizeText(after.path("description").asText(""));
        if (!beforeDescription.equals(afterDescription)) {
            changes.add(new Change("PARAM_DESCRIPTION_CHANGED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "参数 %s 的描述被改写".formatted(param), shortHash(afterDescription)));
        }
    }

    // ---------- 小工具 ----------

    /**
     * 新类型是否比旧类型更宽。
     *
     * <p>{@code string} 是最宽的基本类型（任意内容都能塞），多类型并集也比单一类型宽。
     * 放宽是危险方向：模型按 schema 生成调用，多出来的自由度正是注入指令要利用的东西。
     */
    private static boolean widens(String before, String after) {
        if (after.equals(before)) {
            return false;
        }
        if ("string".equals(after) && !"string".equals(before)) {
            return true;
        }
        return after.contains(",") && !before.contains(",");
    }

    private static String typeOf(JsonNode schema) {
        JsonNode type = schema.path("type");
        if (type.isArray()) {
            List<String> values = new ArrayList<>();
            type.forEach(node -> values.add(node.asText()));
            Collections.sort(values);
            return String.join("|", values);
        }
        return type.asText("");
    }

    /** 没有 enum 时返回 null——"没有约束"与"空取值域"是两回事 */
    private static Set<String> enumValues(JsonNode schema) {
        JsonNode values = schema.path("enum");
        if (!values.isArray()) {
            return null;
        }
        Set<String> result = new LinkedHashSet<>();
        values.forEach(node -> result.add(node.toString()));
        return result;
    }

    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new LinkedHashSet<>();
        if (node.isObject()) {
            node.fieldNames().forEachRemaining(names::add);
        }
        return names;
    }

    private static Set<String> textSet(JsonNode node) {
        Set<String> values = new LinkedHashSet<>();
        if (node.isArray()) {
            node.forEach(element -> values.add(element.asText()));
        }
        return values;
    }

    private static <T> Set<T> difference(Set<T> left, Set<T> right) {
        Set<T> result = new LinkedHashSet<>(left);
        result.removeAll(right);
        return result;
    }

    private static <T> Set<T> intersection(Set<T> left, Set<T> right) {
        Set<T> result = new LinkedHashSet<>(left);
        result.retainAll(right);
        return result;
    }

    private static String shortHash(String text) {
        return ToolFingerprint.sha256(text).substring(0, 16).toLowerCase(Locale.ROOT);
    }
}
