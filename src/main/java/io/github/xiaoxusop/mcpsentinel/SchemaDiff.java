package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * 逐字段比较两份工具定义，产出<b>带类型的变更</b>与<b>未覆盖路径兜底</b>。
 *
 * <p>核心不变量（W02）：
 * <ul>
 *   <li>每条语义分级规则只认领自己实际解释的 JSON Pointer 路径；</li>
 *   <li>任何未被语义规则认领的结构差异路径，无论旁边是否同时存在 {@code TITLE_CHANGED}（INFO）
 *       等已知变更，都会生成 {@code UNGRADED_SCHEMA_CHANGE}（DANGEROUS）并携带具体路径与内容摘要；</li>
 *   <li>类型比较基于类型集合与包含关系（{@code integer ⊂ number}），单一类型扩为联合类型判为放宽；</li>
 *   <li>{@code additionalProperties} 区分缺省允许、显式 {@code true}、显式 {@code false} 与子 Schema 四种状态。</li>
 * </ul>
 */
final class SchemaDiff {

    /** 会被当作约束的关键字。它们的增删改都改变可传内容的自由度 */
    private static final List<String> CONSTRAINTS = List.of(
            "pattern", "format", "maxLength", "minLength", "maximum", "minimum", "multipleOf");

    private SchemaDiff() {
    }

    static List<Change> between(ToolDefinition before, ToolDefinition after, int occurrence) {
        return between(before, after, occurrence, PathChange.between(after.name(), occurrence, before.toJson(), after.toJson()));
    }

    static List<Change> between(ToolDefinition before, ToolDefinition after, int occurrence, List<PathChange> paths) {
        List<Change> changes = new ArrayList<>();
        String name = after.name();

        String beforeDescription = SchemaCanonicalizer.normalizeText(before.description());
        String afterDescription = SchemaCanonicalizer.normalizeText(after.description());
        if (!beforeDescription.equals(afterDescription)) {
            changes.add(new Change("DESCRIPTION_CHANGED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "工具描述被改写（描述会进入模型上下文，是投毒的本体）",
                    shortHash(afterDescription)).at("/description"));
        }

        String beforeTitle = SchemaCanonicalizer.normalizeText(before.title());
        String afterTitle = SchemaCanonicalizer.normalizeText(after.title());
        if (!beforeTitle.equals(afterTitle)) {
            changes.add(new Change("TITLE_CHANGED", name, occurrence, ChangeSeverity.INFO,
                    "标题被改写", shortHash(afterTitle)).at("/title"));
        }

        JsonNode beforeOutput = SchemaCanonicalizer.canonicalize(before.outputSchema());
        JsonNode afterOutput = SchemaCanonicalizer.canonicalize(after.outputSchema());
        if (!beforeOutput.equals(afterOutput)) {
            changes.add(new Change("OUTPUT_SCHEMA_CHANGED", name, occurrence, ChangeSeverity.BREAKING,
                    "出参 schema 被改写（调用方依据它校验返回值）", shortHash(afterOutput.toString())).at("/outputSchema"));
        }

        annotate(
                SchemaCanonicalizer.canonicalizeMetadata(before.annotations()),
                SchemaCanonicalizer.canonicalizeMetadata(after.annotations()),
                name, occurrence, changes);
        inputSchema(
                SchemaCanonicalizer.canonicalize(before.inputSchema()),
                SchemaCanonicalizer.canonicalize(after.inputSchema()),
                name, occurrence, changes);
        return completeCoverage(name, occurrence, paths, changes);
    }

    /** Every structural path must be explained, regardless of other emitted changes. */
    static List<Change> completeCoverage(String name, int occurrence, List<PathChange> paths, List<Change> graded) {
        List<Change> result = new ArrayList<>();
        Set<String> covered = new LinkedHashSet<>();
        for (Change change : graded) {
            List<String> actual = paths.stream().map(PathChange::path).filter(path -> change.paths().stream()
                    .anyMatch(root -> root.isEmpty() || path.equals(root) || path.startsWith(root + "/"))).toList();
            covered.addAll(actual);
            result.add(change.withPaths(actual));
        }
        List<PathChange> remaining = paths.stream().filter(p -> !covered.contains(p.path())).toList();
        if (!remaining.isEmpty()) {
            List<String> pointers = remaining.stream().map(PathChange::path).toList();
            String digestInput = remaining.stream().map(p -> p.path() + "=" + p.before() + "→" + p.after())
                    .collect(java.util.stream.Collectors.joining("\n"));
            result.add(new Change("UNGRADED_SCHEMA_CHANGE", name, occurrence, ChangeSeverity.DANGEROUS,
                    "存在未被分级规则解释的结构路径 " + pointers + "（未知影响，需审查）", shortHash(digestInput), pointers));
        }
        return result;
    }

    // ---------- 注解：声明的风险等级被改写 ----------

    private static void annotate(JsonNode before, JsonNode after, String name, int occurrence,
                                 List<Change> changes) {
        for (String key : List.of("destructiveHint", "readOnlyHint")) {
            JsonNode a = after.get(key), b = before.get(key);
            if (Objects.equals(a, b)) continue;
            if ((a != null && !a.isBoolean()) || (b != null && !b.isBoolean())) continue;
            boolean defaultValue = "destructiveHint".equals(key);
            boolean was = b == null ? defaultValue : b.booleanValue();
            boolean now = a == null ? defaultValue : a.booleanValue();
            boolean dangerous = defaultValue ? !now : now;
            String id = was == now ? "ANNOTATION_CHANGED" : defaultValue ? "ANNOTATION_DESTRUCTIVE_FLIPPED" : "ANNOTATION_READONLY_FLIPPED";
            changes.add(new Change(id, name, occurrence, was == now || !dangerous ? ChangeSeverity.INFO : ChangeSeverity.DANGEROUS,
                    key + (was == now ? " 显式值与缺省值等价" : " %s → %s".formatted(was, now)),
                    shortHash(before + "|" + after)).at("/annotations/" + key));
        }
        if (!Objects.equals(before.get("title"), after.get("title"))) {
            changes.add(new Change("ANNOTATION_CHANGED", name, occurrence, ChangeSeverity.INFO,
                    "注解标题被改写", shortHash(before + "|" + after)).at("/annotations/title"));
        }
        // All other annotation paths stay unclaimed and reach completeCoverage.
    }

    // ---------- 入参 schema（含路径认领与未解释差异兜底） ----------

    private static void inputSchema(JsonNode before, JsonNode after, String name, int occurrence,
                                    List<Change> changes) {
        if (Objects.equals(before, after)) {
            return;
        }
        if (before == null || after == null || !before.isObject() || !after.isObject()) {
            emitUngraded(name, occurrence, List.of("/inputSchema"), after, changes);
            return;
        }

        List<String> unexplainedPaths = new ArrayList<>();
        StringBuilder unexplainedDigestInput = new StringBuilder();

        JsonNode beforeProperties = before.get("properties");
        JsonNode afterProperties = after.get("properties");
        boolean propertiesHandled = false;

        if ((beforeProperties == null || beforeProperties.isObject())
                && (afterProperties == null || afterProperties.isObject())) {
            propertiesHandled = true;
            Set<String> beforeParams = fieldNames(beforeProperties);
            Set<String> afterParams = fieldNames(afterProperties);
            Set<String> beforeRequired = textSet(before.path("required"));
            Set<String> afterRequired = textSet(after.path("required"));

            for (String param : new TreeSet<>(difference(afterParams, beforeParams))) {
                boolean required = afterRequired.contains(param);
                changes.add(new Change(
                        required ? "PARAM_ADDED_REQUIRED" : "PARAM_ADDED_OPTIONAL", name, occurrence,
                        required ? ChangeSeverity.BREAKING : ChangeSeverity.DANGEROUS,
                        "参数 %s %s".formatted(param, required ? "（必填）" : "（可选）"),
                        shortHash(afterProperties.path(param).toString())).at(
                                beforeProperties == null ? "/inputSchema/properties" : "/inputSchema/properties/" + escapePointer(param),
                                required ? "/inputSchema/required" : "/inputSchema/properties/" + escapePointer(param)));
            }
            for (String param : new TreeSet<>(difference(beforeParams, afterParams))) {
                changes.add(new Change("PARAM_REMOVED", name, occurrence, ChangeSeverity.BREAKING,
                        "参数 %s 被移除".formatted(param), shortHash(param)).at(
                                afterProperties == null ? "/inputSchema/properties" : "/inputSchema/properties/" + escapePointer(param),
                                beforeRequired.contains(param) ? "/inputSchema/required" : "/inputSchema/properties/" + escapePointer(param)));
            }
            for (String param : new TreeSet<>(intersection(beforeParams, afterParams))) {
                compareParameter(param, beforeProperties.path(param), afterProperties.path(param),
                        name, occurrence, changes, unexplainedPaths, unexplainedDigestInput);
            }
        }

        // required 集合比较
        boolean requiredHandled = compareRequired(before, after, name, occurrence, changes);
        if (!requiredHandled && !Objects.equals(before.get("required"), after.get("required"))) {
            recordUnexplained("/inputSchema/required", after.get("required"),
                    unexplainedPaths, unexplainedDigestInput);
        }

        // additionalProperties 四态比较（F07）
        boolean additionalPropsHandled = compareAdditionalProperties(
                before.get("additionalProperties"), after.get("additionalProperties"),
                name, occurrence, changes);
        if (!additionalPropsHandled
                && !Objects.equals(before.get("additionalProperties"), after.get("additionalProperties"))) {
            collectDiffPaths(before.get("additionalProperties"), after.get("additionalProperties"),
                    "/inputSchema/additionalProperties", unexplainedPaths, unexplainedDigestInput);
        }

        // 检查顶层其余字段（以及未能按对象处理的 properties）
        Set<String> rootKeys = new TreeSet<>(fieldNames(before));
        rootKeys.addAll(fieldNames(after));
        for (String key : rootKeys) {
            if ("required".equals(key) || "additionalProperties".equals(key)) {
                continue;
            }
            if ("properties".equals(key) && propertiesHandled) {
                continue;
            }
            JsonNode bVal = before.get(key);
            JsonNode aVal = after.get(key);
            if (!Objects.equals(bVal, aVal)) {
                collectDiffPaths(bVal, aVal, "/inputSchema/" + escapePointer(key),
                        unexplainedPaths, unexplainedDigestInput);
            }
        }

        if (!unexplainedPaths.isEmpty()) {
            emitUngraded(name, occurrence, unexplainedPaths, unexplainedDigestInput.toString(), changes);
        }
    }

    private static boolean compareRequired(JsonNode before, JsonNode after, String name, int occurrence,
                                           List<Change> changes) {
        JsonNode bReqNode = before.get("required");
        JsonNode aReqNode = after.get("required");
        if (Objects.equals(bReqNode, aReqNode)) {
            return true;
        }
        if ((bReqNode != null && !bReqNode.isArray()) || (aReqNode != null && !aReqNode.isArray())) {
            return false;
        }
        Set<String> beforeParams = fieldNames(before.get("properties"));
        Set<String> afterParams = fieldNames(after.get("properties"));
        Set<String> beforeRequired = textSet(before.path("required"));
        Set<String> afterRequired = textSet(after.path("required"));

        int beforeChanges = changes.size();
        for (String param : new TreeSet<>(difference(difference(afterRequired, beforeRequired),
                difference(afterParams, beforeParams)))) {
            changes.add(new Change("REQUIRED_ADDED", name, occurrence, ChangeSeverity.BREAKING,
                    "参数 %s 变为必填".formatted(param), shortHash(param)).at("/inputSchema/required"));
        }
        for (String param : new TreeSet<>(difference(difference(beforeRequired, afterRequired),
                difference(beforeParams, afterParams)))) {
            changes.add(new Change("REQUIRED_REMOVED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "参数 %s 不再必填（调用方可以省略它了）".formatted(param), shortHash(param)).at("/inputSchema/required"));
        }
        // 若差异完全由新增/删除必填参数（PARAM_ADDED_REQUIRED / PARAM_REMOVED）解释，也视为已认领
        boolean explainedByAddedOrRemovedParam =
                difference(afterRequired, beforeRequired).stream()
                        .allMatch(p -> !beforeParams.contains(p) && afterParams.contains(p))
                && difference(beforeRequired, afterRequired).stream()
                        .allMatch(p -> beforeParams.contains(p) && !afterParams.contains(p))
                && (!difference(afterRequired, beforeRequired).isEmpty()
                        || !difference(beforeRequired, afterRequired).isEmpty());
        return changes.size() > beforeChanges || explainedByAddedOrRemovedParam;
    }

    /**
     * F07 修正：区分缺省（OMITTED）、显式 {@code true}、显式 {@code false} 与子 Schema 四种状态。
     */
    private static boolean compareAdditionalProperties(JsonNode beforeNode, JsonNode afterNode,
                                                       String name, int occurrence, List<Change> changes) {
        if (Objects.equals(beforeNode, afterNode)) {
            return true;
        }
        AdditionalPropsState before = AdditionalPropsState.of(beforeNode);
        AdditionalPropsState after = AdditionalPropsState.of(afterNode);

        if (before == AdditionalPropsState.OTHER || after == AdditionalPropsState.OTHER) {
            return false;
        }
        if (before == AdditionalPropsState.SCHEMA && after == AdditionalPropsState.SCHEMA) {
            // 两个不同的子 Schema 约束：无法简单归为打开或关闭，交由 UNGRADED_SCHEMA_CHANGE 保守阻断
            return false;
        }
        if (before == AdditionalPropsState.FALSE
                && (after == AdditionalPropsState.TRUE
                    || after == AdditionalPropsState.OMITTED
                    || after == AdditionalPropsState.SCHEMA)) {
            String detail = after == AdditionalPropsState.SCHEMA
                    ? "additionalProperties 由关闭放宽为子 Schema 约束"
                    : "additionalProperties 由关闭变为打开：未声明的字段会被静默接受";
            changes.add(new Change("SCHEMA_OPENED", name, occurrence, ChangeSeverity.DANGEROUS,
                    detail, shortHash("open:" + afterNode)).at("/inputSchema/additionalProperties"));
            return true;
        }
        if (before == AdditionalPropsState.OMITTED && after == AdditionalPropsState.TRUE) {
            changes.add(new Change("SCHEMA_DEFAULT_EXPLICIT", name, occurrence, ChangeSeverity.INFO,
                    "additionalProperties 显式写为 true（缺省本就允许额外属性）", shortHash("explicit:true")).at("/inputSchema/additionalProperties"));
            return true;
        }
        if (before == AdditionalPropsState.TRUE && after == AdditionalPropsState.OMITTED) {
            changes.add(new Change("SCHEMA_DEFAULT_EXPLICIT", name, occurrence, ChangeSeverity.INFO,
                    "additionalProperties 恢复缺省允许", shortHash("omitted")).at("/inputSchema/additionalProperties"));
            return true;
        }
        if ((before == AdditionalPropsState.TRUE || before == AdditionalPropsState.OMITTED)
                && (after == AdditionalPropsState.FALSE || after == AdditionalPropsState.SCHEMA)) {
            String detail = after == AdditionalPropsState.SCHEMA
                    ? "additionalProperties 由允许任意属性收窄为子 Schema 约束"
                    : "additionalProperties 由打开变为关闭";
            changes.add(new Change("SCHEMA_CLOSED", name, occurrence, ChangeSeverity.BREAKING,
                    detail, shortHash("closed:" + afterNode)).at("/inputSchema/additionalProperties"));
            return true;
        }
        if (before == AdditionalPropsState.SCHEMA
                && (after == AdditionalPropsState.TRUE || after == AdditionalPropsState.OMITTED)) {
            changes.add(new Change("SCHEMA_OPENED", name, occurrence, ChangeSeverity.DANGEROUS,
                    "additionalProperties 去掉了子 Schema 约束：未声明的字段会被静默接受",
                    shortHash("open:" + afterNode)).at("/inputSchema/additionalProperties"));
            return true;
        }
        if (before == AdditionalPropsState.SCHEMA && after == AdditionalPropsState.FALSE) {
            changes.add(new Change("SCHEMA_CLOSED", name, occurrence, ChangeSeverity.BREAKING,
                    "additionalProperties 由子 Schema 约束变为关闭",
                    shortHash("closed")).at("/inputSchema/additionalProperties"));
            return true;
        }
        return false;
    }

    private enum AdditionalPropsState {
        OMITTED, TRUE, FALSE, SCHEMA, OTHER;

        static AdditionalPropsState of(JsonNode node) {
            if (node == null || node.isMissingNode()) {
                return OMITTED;
            }
            if (node.isBoolean()) {
                return node.booleanValue() ? TRUE : FALSE;
            }
            if (node.isObject()) {
                return SCHEMA;
            }
            return OTHER;
        }
    }

    private static void compareParameter(String param, JsonNode before, JsonNode after,
                                         String name, int occurrence, List<Change> changes,
                                         List<String> unexplainedPaths, StringBuilder unexplainedDigestInput) {
        if (Objects.equals(before, after)) {
            return;
        }
        String paramPointer = "/inputSchema/properties/" + escapePointer(param);
        if (before == null || after == null || !before.isObject() || !after.isObject()) {
            recordUnexplained(paramPointer, after, unexplainedPaths, unexplainedDigestInput);
            return;
        }

        Set<String> claimedFields = new LinkedHashSet<>();

        // 1. type 比较（F04：使用类型集合与 integer ⊂ number 包含关系）
        JsonNode bTypeNode = before.get("type");
        JsonNode aTypeNode = after.get("type");
        if (Objects.equals(bTypeNode, aTypeNode)) {
            claimedFields.add("type");
        } else if (isSupportedTypeNode(bTypeNode) && isSupportedTypeNode(aTypeNode)) {
            Set<String> beforeTypes = typeSet(before);
            Set<String> afterTypes = typeSet(after);
            String beforeType = formatTypes(beforeTypes);
            String afterType = formatTypes(afterTypes);
            if (!beforeTypes.equals(afterTypes) || !Objects.equals(bTypeNode, aTypeNode)) {
                boolean widened = widens(beforeTypes, afterTypes);
                boolean equivalent = coversAll(beforeTypes, afterTypes) && coversAll(afterTypes, beforeTypes);
                changes.add(new Change(equivalent ? "PARAM_TYPE_EQUIVALENT" : widened ? "PARAM_TYPE_WIDENED" : "PARAM_TYPE_CHANGED",
                        name, occurrence, equivalent ? ChangeSeverity.INFO : widened ? ChangeSeverity.DANGEROUS : ChangeSeverity.BREAKING,
                        "参数 %s 的类型 %s → %s".formatted(param, beforeType, afterType),
                        shortHash(afterType)).at(paramPointer + "/type"));
                claimedFields.add("type");
            }
        }

        // 2. enum 比较
        JsonNode bEnumNode = before.get("enum");
        JsonNode aEnumNode = after.get("enum");
        if (Objects.equals(bEnumNode, aEnumNode)) {
            claimedFields.add("enum");
        } else {
            Set<String> beforeEnum = enumValues(before);
            Set<String> afterEnum = enumValues(after);
            if (beforeEnum != null && afterEnum == null && aEnumNode == null) {
                changes.add(new Change("PARAM_ENUM_REMOVED", name, occurrence, ChangeSeverity.DANGEROUS,
                        "参数 %s 去掉了 enum 约束：取值域变成任意值".formatted(param), shortHash("none")).at(paramPointer + "/enum"));
                claimedFields.add("enum");
            } else if (beforeEnum == null && bEnumNode == null && afterEnum != null) {
                changes.add(new Change("PARAM_ENUM_ADDED", name, occurrence, ChangeSeverity.BREAKING,
                        "参数 %s 新增了 enum 约束".formatted(param), shortHash(afterEnum.toString())).at(paramPointer + "/enum"));
                claimedFields.add("enum");
            } else if (beforeEnum != null && afterEnum != null) {
                if (afterEnum.containsAll(beforeEnum) && !afterEnum.equals(beforeEnum)) {
                    changes.add(new Change("PARAM_ENUM_WIDENED", name, occurrence, ChangeSeverity.DANGEROUS,
                            "参数 %s 的取值域变宽：%s → %s".formatted(param, beforeEnum, afterEnum),
                            shortHash(afterEnum.toString())).at(paramPointer + "/enum"));
                    claimedFields.add("enum");
                } else if (beforeEnum.containsAll(afterEnum) && !afterEnum.equals(beforeEnum)) {
                    changes.add(new Change("PARAM_ENUM_NARROWED", name, occurrence, ChangeSeverity.BREAKING,
                            "参数 %s 的取值域变窄：%s → %s".formatted(param, beforeEnum, afterEnum),
                            shortHash(afterEnum.toString())).at(paramPointer + "/enum"));
                    claimedFields.add("enum");
                } else if (!afterEnum.equals(beforeEnum)) {
                    changes.add(new Change("PARAM_ENUM_CHANGED", name, occurrence, ChangeSeverity.BREAKING,
                            "参数 %s 的取值域改变：%s → %s".formatted(param, beforeEnum, afterEnum),
                            shortHash(afterEnum.toString())).at(paramPointer + "/enum"));
                    claimedFields.add("enum");
                }
            }
        }

        // 3. 7 项标量约束比较
        for (String constraint : CONSTRAINTS) {
            if ((before.path(constraint).isNull() || after.path(constraint).isNull())
                    && !Objects.equals(before.get(constraint), after.get(constraint))) continue;
            JsonNode beforeValue = before.path(constraint);
            JsonNode afterValue = after.path(constraint);
            boolean beforeHas = !beforeValue.isMissingNode() && !beforeValue.isNull();
            boolean afterHas = !afterValue.isMissingNode() && !afterValue.isNull();
            if (!beforeHas && !afterHas) {
                claimedFields.add(constraint);
            } else if (beforeHas && !afterHas) {
                changes.add(new Change("PARAM_CONSTRAINT_REMOVED", name, occurrence, ChangeSeverity.DANGEROUS,
                        "参数 %s 去掉了 %s 约束".formatted(param, constraint), shortHash("none")).at(paramPointer + "/" + constraint));
                claimedFields.add(constraint);
            } else if (!beforeHas && afterHas) {
                changes.add(new Change("PARAM_CONSTRAINT_ADDED", name, occurrence, ChangeSeverity.BREAKING,
                        "参数 %s 新增 %s 约束".formatted(param, constraint),
                        shortHash(afterValue.toString())).at(paramPointer + "/" + constraint));
                claimedFields.add(constraint);
            } else if (beforeValue.equals(afterValue)) {
                claimedFields.add(constraint);
            } else {
                boolean narrower = beforeValue.isNumber() && afterValue.isNumber() && switch (constraint) {
                    case "maxLength", "maximum" -> afterValue.decimalValue().compareTo(beforeValue.decimalValue()) < 0;
                    case "minLength", "minimum" -> afterValue.decimalValue().compareTo(beforeValue.decimalValue()) > 0;
                    default -> false;
                };
                changes.add(new Change("PARAM_CONSTRAINT_CHANGED", name, occurrence,
                        narrower ? ChangeSeverity.BREAKING : ChangeSeverity.DANGEROUS,
                        "参数 %s 的 %s 由 %s 改为 %s".formatted(param, constraint, beforeValue, afterValue),
                        shortHash(afterValue.toString())).at(paramPointer + "/" + constraint));
                claimedFields.add(constraint);
            }
        }

        // 4. 参数 description 比较
        JsonNode bDescNode = before.get("description");
        JsonNode aDescNode = after.get("description");
        if (Objects.equals(bDescNode, aDescNode)) {
            claimedFields.add("description");
        } else if ((bDescNode == null || bDescNode.isTextual()) && (aDescNode == null || aDescNode.isTextual())) {
            String beforeDescription = SchemaCanonicalizer.normalizeText(before.path("description").asText(""));
            String afterDescription = SchemaCanonicalizer.normalizeText(after.path("description").asText(""));
            if (!beforeDescription.equals(afterDescription)) {
                changes.add(new Change("PARAM_DESCRIPTION_CHANGED", name, occurrence, ChangeSeverity.DANGEROUS,
                        "参数 %s 的描述被改写".formatted(param), shortHash(afterDescription)).at(paramPointer + "/description"));
            }
            claimedFields.add("description");
        }

        // 5. 参数内其余未被认领的字段（如嵌套 properties / items / oneOf / const / additionalProperties 等）
        Set<String> allParamKeys = new TreeSet<>(fieldNames(before));
        allParamKeys.addAll(fieldNames(after));
        for (String key : allParamKeys) {
            if (claimedFields.contains(key)) {
                continue;
            }
            JsonNode bVal = before.get(key);
            JsonNode aVal = after.get(key);
            if (!Objects.equals(bVal, aVal)) {
                collectDiffPaths(bVal, aVal, paramPointer + "/" + escapePointer(key),
                        unexplainedPaths, unexplainedDigestInput);
            }
        }
    }

    private static void collectDiffPaths(JsonNode before, JsonNode after, String pointer,
                                         List<String> paths, StringBuilder digestInput) {
        if (Objects.equals(before, after)) {
            return;
        }
        if (before != null && after != null && before.isObject() && after.isObject()) {
            Set<String> keys = new TreeSet<>(fieldNames(before));
            keys.addAll(fieldNames(after));
            for (String key : keys) {
                String childPointer = pointer + "/" + escapePointer(key);
                if (!before.has(key) || !after.has(key)) {
                    recordUnexplained(childPointer, after.get(key), paths, digestInput);
                } else {
                    collectDiffPaths(before.get(key), after.get(key), childPointer, paths, digestInput);
                }
            }
            return;
        }
        recordUnexplained(pointer, after, paths, digestInput);
    }

    private static void recordUnexplained(String pointer, JsonNode afterNode,
                                          List<String> paths, StringBuilder digestInput) {
        paths.add(pointer);
        digestInput.append(pointer).append('=').append(afterNode == null ? "<removed>" : afterNode.toString()).append('\n');
    }

    private static void emitUngraded(String name, int occurrence, List<String> paths, Object digestSource,
                                     List<Change> changes) {
        String joinedPaths = String.join(", ", paths);
        changes.add(new Change("UNGRADED_SCHEMA_CHANGE", name, occurrence,
                ChangeSeverity.DANGEROUS,
                "schema 存在未覆盖路径变化 [" + joinedPaths + "]（未知影响，需审查；请人工核对后 --accept-changes）",
                shortHash(String.valueOf(digestSource)), paths));
    }

    private static String escapePointer(String segment) {
        return segment.replace("~", "~0").replace("/", "~1");
    }

    // ---------- 类型与集合工具 ----------

    private static boolean isSupportedTypeNode(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return true;
        }
        if (node.isTextual()) {
            return !node.asText("").isBlank();
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (!item.isTextual() || item.asText("").isBlank()) {
                    return false;
                }
            }
            return !node.isEmpty();
        }
        return false;
    }

    /**
     * F04 修正：基于类型集合与 {@code integer ⊂ number} 包含关系判断是否放宽。
     */
    private static boolean widens(Set<String> before, Set<String> after) {
        if (after.equals(before)) {
            return false;
        }
        if (!before.isEmpty() && after.isEmpty()) {
            // 移除了 type 约束
            return true;
        }
        if (before.isEmpty()) {
            return false;
        }
        return coversAll(after, before) && !coversAll(before, after);
    }

    private static boolean coversAll(Set<String> superset, Set<String> subset) {
        for (String requiredType : subset) {
            boolean covered = superset.contains(requiredType)
                    || ("integer".equals(requiredType) && superset.contains("number"));
            if (!covered) {
                return false;
            }
        }
        return true;
    }

    private static Set<String> typeSet(JsonNode schema) {
        JsonNode type = schema.path("type");
        if (type.isArray()) {
            List<String> values = new ArrayList<>();
            type.forEach(node -> {
                String text = node.asText("");
                if (!text.isBlank()) {
                    values.add(text);
                }
            });
            Collections.sort(values);
            return new LinkedHashSet<>(values);
        }
        String single = type.asText("");
        return single.isBlank() ? Set.of() : Set.of(single);
    }

    private static String formatTypes(Set<String> types) {
        return types.isEmpty() ? "<any>" : String.join("|", types);
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
        if (node != null && node.isObject()) {
            node.fieldNames().forEachRemaining(names::add);
        }
        return names;
    }

    private static Set<String> textSet(JsonNode node) {
        Set<String> values = new LinkedHashSet<>();
        if (node != null && node.isArray()) {
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
