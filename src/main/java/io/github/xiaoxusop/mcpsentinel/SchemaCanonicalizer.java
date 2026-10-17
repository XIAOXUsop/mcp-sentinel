package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.DecimalNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * JSON Schema 的<b>上下文感知语义级</b>规范化。
 *
 * <p>指纹要回答的问题是"这份定义变了吗"，而"变了"应当是<b>语义</b>变了，不是字节变了。
 * 直接对 JSON 求哈希会把下面这些语义等价的情形判成变更：
 * <ul>
 *   <li>{@code required: ["q","limit"]} 与 {@code ["limit","q"]}——同一个 schema；</li>
 *   <li>{@code "maxLength": 100} 与 {@code 100.0}——同一个约束；</li>
 *   <li>{@code enum:["fast","deep"]} 与 {@code ["deep","fast"]}——外层 enum 候选项是集合；</li>
 *   <li>Schema 注释 {@code description} / {@code title} 尾部多一个空格或 CRLF/LF 差异。</li>
 * </ul>
 *
 * <p><b>为什么必须区分遍历上下文（v2 修正）</b>：
 * <ul>
 *   <li><b>F01（{@code oneOf} 分支不能去重）</b>：JSON Schema 的 {@code oneOf} 要求<b>恰好一个</b>分支匹配。
 *       {@code oneOf: [integer, integer, string]} 对整数会匹配两个分支从而拒绝整数，
 *       而去重后的 {@code [integer, string]} 会接受整数。因此 {@code oneOf} 只能按规范形稳定排序，
 *       <b>必须保留重复分支次数</b>（多重集语义）。</li>
 *   <li><b>F02（Schema 节点与实例值节点必须隔离）</b>：{@code enum}、{@code const}、{@code default}、
 *       {@code examples} 内部承载的是<b>实例数据</b>而非子 Schema。例如 {@code enum: [[1,2]]} 与
 *       {@code enum: [[2,1]]} 允许的是两个完全不同的数组实例；实例对象里的 {@code "description"}、
 *       {@code "title"}、{@code "required"} 也只是普通业务字段名，不能被裁剪空白或当成集合去重。</li>
 *   <li><b>属性映射隔离</b>：{@code properties}、{@code $defs}、{@code definitions}、
 *       {@code patternProperties}、{@code dependentSchemas} 的直接子键是<b>参数名或定义名</b>
 *       （即使参数名叫 {@code enum} 或 {@code title}），其对应的值才是子 Schema。</li>
 *   <li><b>未知扩展保守保留</b>：不在已知 Schema 关键字表中的扩展字段（如 {@code x-*}），
 *       仅对对象键排序和数值写法归一，不猜测其数组顺序或字符串空白语义。</li>
 * </ul>
 */
public final class SchemaCanonicalizer {

    /**
     * 规范化规则版本。
     *
     * <p>v2 区分 Schema / 实例值 / 属性映射上下文，修正 {@code oneOf} 分支去重与 {@code enum} 内层数组重排。
     */
    public static final int VERSION = 2;

    /** 默认最大嵌套深度，防止恶意超深 JSON 导致栈溢出 */
    public static final int MAX_DEPTH = 64;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 遍历上下文。
     */
    private enum Context {
        /** 标准 JSON Schema 节点 */
        SCHEMA,
        /** 键为属性名/定义名、值为子 Schema 的映射对象（如 properties / $defs） */
        SCHEMA_MAP,
        /** dependentRequired：键为属性名、值为字符串集合的映射对象 */
        DEPENDENT_REQUIRED_MAP,
        /** 实例数据或未知扩展：对象键排序、数值归一，但数组严格保序且保留重复、字符串保留原始空白 */
        INSTANCE
    }

    /** 值为「属性名/定义名 → 子 Schema」映射的关键字 */
    private static final Set<String> SCHEMA_MAP_KEYWORDS = Set.of(
            "properties", "patternProperties", "$defs", "definitions", "dependentSchemas");

    /** 值为单个子 Schema（对象或布尔 Schema）的关键字 */
    private static final Set<String> SUBSCHEMA_KEYWORDS = Set.of(
            "items", "additionalProperties", "unevaluatedProperties", "unevaluatedItems",
            "not", "if", "then", "else", "contains", "propertyNames", "additionalItems", "contentSchema");

    /** 值为子 Schema 集合（顺序与重复均不影响语义）的关键字 */
    private static final Set<String> SET_SUBSCHEMA_KEYWORDS = Set.of("allOf", "anyOf");

    /** 值为字符串集合（顺序与重复均不影响语义）的关键字 */
    private static final Set<String> SET_STRING_KEYWORDS = Set.of("required", "type");

    /** 值为有序子 Schema 数组（tuple 校验，顺序与重复均有语义）的关键字 */
    private static final Set<String> ORDERED_SUBSCHEMA_ARRAY_KEYWORDS = Set.of("prefixItems", "items");

    /** 值为实例数据的关键字 */
    private static final Set<String> INSTANCE_KEYWORDS = Set.of("const", "default", "examples");

    /** Schema 上的描述性文本关键字：首尾空白与换行风格不构成语义差异 */
    private static final Set<String> TEXT_KEYWORDS = Set.of("description", "title");

    private SchemaCanonicalizer() {
    }

    /** 按默认 JSON Schema 上下文规范化节点 */
    public static JsonNode canonicalize(JsonNode node) {
        if (node != null) SchemaValidation.validate(node);
        // JSON Pointer references can address array indices. Reordering any array
        // in such a document can change its meaning, even if the keyword itself
        // normally has set semantics. Preserve structure conservatively.
        return canonicalize(node, hasReference(node, 0) ? Context.INSTANCE : Context.SCHEMA, 0);
    }

    private static boolean hasReference(JsonNode node, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("JSON 结构嵌套深度超过安全上限 " + MAX_DEPTH);
        if (node == null) return false;
        if (node.isObject() && (node.has("$ref") || node.has("$dynamicRef") || node.has("$recursiveRef"))) return true;
        for (JsonNode child : node) if (hasReference(child, depth + 1)) return true;
        return false;
    }

    /** 按实例/元数据对象上下文规范化（用于 annotations 等非 Schema 结构，仅对顶层 title/description 归一） */
    public static JsonNode canonicalizeMetadata(JsonNode node) {
        if (node == null || node.isNull()) {
            return MAPPER.nullNode();
        }
        if (!node.isObject()) {
            return canonicalize(node, Context.INSTANCE, 0);
        }
        ObjectNode result = MAPPER.createObjectNode();
        Map<String, JsonNode> sorted = sortedFields(node);
        sorted.forEach((key, value) -> {
            if (TEXT_KEYWORDS.contains(key) && value != null && value.isTextual()) {
                result.put(key, normalizeText(value.textValue()));
            } else {
                result.set(key, canonicalize(value, Context.INSTANCE, 1));
            }
        });
        return result;
    }

    private static JsonNode canonicalize(JsonNode node, Context context, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON 结构嵌套深度超过安全上限 " + MAX_DEPTH);
        }
        if (node == null || node.isNull()) {
            return MAPPER.nullNode();
        }
        if (node.isNumber()) {
            return normalizeNumber(node);
        }
        if (node.isBoolean() || node.isTextual()) {
            return node;
        }
        if (node.isArray()) {
            ArrayNode array = MAPPER.createArrayNode();
            for (JsonNode element : node) {
                array.add(canonicalize(element, Context.INSTANCE, depth + 1));
            }
            return array;
        }
        if (node.isObject()) {
            return switch (context) {
                case SCHEMA -> canonicalizeSchemaObject(node, depth);
                case SCHEMA_MAP -> canonicalizeSchemaMap(node, depth);
                case DEPENDENT_REQUIRED_MAP -> canonicalizeDependentRequiredMap(node, depth);
                case INSTANCE -> canonicalizeInstanceObject(node, depth);
            };
        }
        return node;
    }

    private static ObjectNode canonicalizeSchemaObject(JsonNode node, int depth) {
        ObjectNode result = MAPPER.createObjectNode();
        Map<String, JsonNode> sorted = sortedFields(node);
        sorted.forEach((key, value) -> result.set(key, canonicalizeSchemaField(key, value, depth + 1)));
        return result;
    }

    private static JsonNode canonicalizeSchemaField(String key, JsonNode value, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON 结构嵌套深度超过安全上限 " + MAX_DEPTH);
        }
        if (value == null || value.isNull()) {
            return MAPPER.nullNode();
        }
        if (TEXT_KEYWORDS.contains(key) && value.isTextual()) {
            return MAPPER.getNodeFactory().textNode(normalizeText(value.textValue()));
        }
        if (SCHEMA_MAP_KEYWORDS.contains(key) && value.isObject()) {
            return canonicalize(value, Context.SCHEMA_MAP, depth);
        }
        if ("dependentRequired".equals(key) && value.isObject()) {
            return canonicalize(value, Context.DEPENDENT_REQUIRED_MAP, depth);
        }
        if (INSTANCE_KEYWORDS.contains(key)) {
            return canonicalize(value, Context.INSTANCE, depth);
        }
        if ("enum".equals(key) && value.isArray()) {
            // enum 的每个候选项本身是实例值（内部数组必须保序、内部字符串不裁空白），
            // 但外层 enum 数组是集合语义（顺序与重复候选项不影响取值域）。
            List<JsonNode> elements = new ArrayList<>();
            for (JsonNode element : value) {
                elements.add(canonicalize(element, Context.INSTANCE, depth + 1));
            }
            return deduplicatedSortedArray(elements);
        }
        if (SET_STRING_KEYWORDS.contains(key) && value.isArray()) {
            List<JsonNode> elements = new ArrayList<>();
            for (JsonNode element : value) {
                if (!element.isTextual()) throw new IllegalArgumentException(key + " 必须为字符串数组");
                elements.add(canonicalize(element, Context.INSTANCE, depth + 1));
            }
            if (deduplicatedSortedArray(elements).size() != elements.size()) {
                throw new IllegalArgumentException(key + " 不能包含重复条目");
            }
            return deduplicatedSortedArray(elements);
        }
        if (SET_SUBSCHEMA_KEYWORDS.contains(key) && value.isArray()) {
            List<JsonNode> elements = new ArrayList<>();
            for (JsonNode element : value) {
                elements.add(canonicalize(element, Context.SCHEMA, depth + 1));
            }
            return deduplicatedSortedArray(elements);
        }
        if ("oneOf".equals(key) && value.isArray()) {
            // F01 修正：oneOf 要求恰好一个分支成立。分支顺序无关，但重复分支会禁止该分支匹配通过，
            // 因此只做稳定排序、保留重复次数（多重集语义），绝不去重。
            List<JsonNode> elements = new ArrayList<>();
            for (JsonNode element : value) {
                elements.add(canonicalize(element, Context.SCHEMA, depth + 1));
            }
            elements.sort(Comparator.comparing(JsonNode::toString));
            ArrayNode array = MAPPER.createArrayNode();
            elements.forEach(array::add);
            return array;
        }
        if (ORDERED_SUBSCHEMA_ARRAY_KEYWORDS.contains(key) && value.isArray()) {
            ArrayNode array = MAPPER.createArrayNode();
            for (JsonNode element : value) {
                array.add(canonicalize(element, Context.SCHEMA, depth + 1));
            }
            return array;
        }
        if (SUBSCHEMA_KEYWORDS.contains(key) && (value.isObject() || value.isBoolean())) {
            return canonicalize(value, Context.SCHEMA, depth);
        }
        // 其余已知数值/文本关键字（如 maxLength、minimum、pattern、$ref）或未知扩展关键字：
        // 采用保守的实例级规范化（对象键排序、数值归一，不重排数组、不裁剪字符串）。
        return canonicalize(value, Context.INSTANCE, depth);
    }

    private static ObjectNode canonicalizeSchemaMap(JsonNode node, int depth) {
        ObjectNode result = MAPPER.createObjectNode();
        Map<String, JsonNode> sorted = sortedFields(node);
        sorted.forEach((propName, propSchema) -> {
            if (propSchema != null && (propSchema.isObject() || propSchema.isBoolean())) {
                result.set(propName, canonicalize(propSchema, Context.SCHEMA, depth + 1));
            } else {
                result.set(propName, canonicalize(propSchema, Context.INSTANCE, depth + 1));
            }
        });
        return result;
    }

    private static ObjectNode canonicalizeDependentRequiredMap(JsonNode node, int depth) {
        ObjectNode result = MAPPER.createObjectNode();
        Map<String, JsonNode> sorted = sortedFields(node);
        sorted.forEach((propName, requiredList) -> {
            if (requiredList != null && requiredList.isArray()) {
                List<JsonNode> elements = new ArrayList<>();
                for (JsonNode element : requiredList) {
                    elements.add(canonicalize(element, Context.INSTANCE, depth + 1));
                }
                result.set(propName, deduplicatedSortedArray(elements));
            } else {
                result.set(propName, canonicalize(requiredList, Context.INSTANCE, depth + 1));
            }
        });
        return result;
    }

    private static ObjectNode canonicalizeInstanceObject(JsonNode node, int depth) {
        ObjectNode result = MAPPER.createObjectNode();
        Map<String, JsonNode> sorted = sortedFields(node);
        sorted.forEach((key, value) -> result.set(key, canonicalize(value, Context.INSTANCE, depth + 1)));
        return result;
    }

    private static Map<String, JsonNode> sortedFields(JsonNode objectNode) {
        Map<String, JsonNode> sorted = new TreeMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            sorted.put(field.getKey(), field.getValue());
        }
        return sorted;
    }

    private static ArrayNode deduplicatedSortedArray(List<JsonNode> elements) {
        Map<String, JsonNode> unique = new TreeMap<>();
        for (JsonNode element : elements) {
            unique.putIfAbsent(element.toString(), element);
        }
        ArrayNode result = MAPPER.createArrayNode();
        unique.values().forEach(result::add);
        return result;
    }

    /**
     * 数值归一：{@code 100} / {@code 100.0} / {@code 1e2} 是同一个数。
     */
    private static JsonNode normalizeNumber(JsonNode node) {
        try {
            BigDecimal value = node.decimalValue().stripTrailingZeros();
            // Keep scientific notation: expanding e.g. 1e100000000 would turn
            // a tiny input into a huge allocation during hashing.
            return DecimalNode.valueOf(value);
        } catch (ArithmeticException | NumberFormatException e) {
            return node;
        }
    }

    /**
     * 描述性文本归一：换行统一为 LF，去掉首尾空白；不动内部空白。
     */
    public static String normalizeText(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("\r\n", "\n").replace('\r', '\n').strip();
    }
}
