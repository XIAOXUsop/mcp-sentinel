package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.DecimalNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * JSON Schema 的**语义级**规范化。
 *
 * <p>指纹要回答的问题是"这份定义变了吗"，而"变了"应当是**语义**变了，不是字节变了。
 * 直接对 JSON 求哈希会把下面这些语义等价的情形判成变更——实测全部误报：
 * <ul>
 *   <li>{@code required: ["q","limit"]} 与 {@code ["limit","q"]}——同一个 schema；</li>
 *   <li>{@code "maxLength": 100} 与 {@code 100.0}——同一个约束；</li>
 *   <li>{@code enum:["fast","deep"]} 与 {@code ["deep","fast"]}——enum 是集合；</li>
 *   <li>描述尾部多一个空格。</li>
 * </ul>
 * 服务端用 Set / Map 的迭代顺序生成 {@code required} 是极常见的实现，所以这不是理论问题：
 * 一个会因为无关重排而变红的 CI 门禁，在被人信任之前就会被关掉。
 *
 * <p><b>保守是刻意的</b>：只对**明确知道是集合语义**的关键字排序，其余一律保持原序。
 * 宁可漏归一（退化成字节比较），不可错归一（把真实变更吃掉）。
 * {@code prefixItems} 与数组形式的 {@code items} 是 tuple 校验，顺序有语义，必须保序；
 * {@code enum} 里的字符串可能带空白（{@code " a "} 与 {@code "a"} 是两个不同的取值），
 * 因此文本裁剪只作用于描述性关键字。
 */
public final class SchemaCanonicalizer {

    /**
     * 规范化规则版本。
     *
     * <p>规则一旦变化，旧基线会产生一次**全量假 diff**——那是规则升级的正常代价，
     * 但绝不能让使用者误以为是攻击。写进 lockfile 后即可给出明确提示。
     */
    public static final int VERSION = 1;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 值是**集合**的关键字：数组元素的顺序与重复都不影响语义。
     *
     * <p>刻意只列这几个。{@code examples}、{@code prefixItems}、数组形式的 {@code items}
     * 都不在其中——它们要么顺序有意义，要么顺序可能有意义，归一的收益抵不上错归一的风险。
     */
    private static final Set<String> SET_VALUED_KEYWORDS =
            Set.of("required", "enum", "type", "allOf", "anyOf", "oneOf");

    /** 值是**描述性文本**的关键字：首尾空白与换行风格不构成语义差异 */
    private static final Set<String> TEXT_KEYWORDS = Set.of("description", "title");

    private SchemaCanonicalizer() {
    }

    /** 规范化任意 JSON 节点 */
    public static JsonNode canonicalize(JsonNode node) {
        return canonicalize(node, null);
    }

    private static JsonNode canonicalize(JsonNode node, String key) {
        if (node == null || node.isNull()) {
            return MAPPER.nullNode();
        }
        if (node.isObject()) {
            ObjectNode result = MAPPER.createObjectNode();
            Map<String, JsonNode> sorted = new TreeMap<>();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                sorted.put(field.getKey(), field.getValue());
            }
            sorted.forEach((childKey, value) -> result.set(childKey, canonicalize(value, childKey)));
            return result;
        }
        if (node.isArray()) {
            List<JsonNode> elements = new ArrayList<>();
            node.forEach(element -> elements.add(canonicalize(element, key)));
            ArrayNode result = MAPPER.createArrayNode();
            if (SET_VALUED_KEYWORDS.contains(key)) {
                // 按规范形排序去重——{@code ["a","b"]} 与 {@code ["b","a"]} 是同一个集合
                Map<String, JsonNode> unique = new TreeMap<>();
                for (JsonNode element : elements) {
                    unique.putIfAbsent(element.toString(), element);
                }
                unique.values().forEach(result::add);
            } else {
                elements.forEach(result::add);
            }
            return result;
        }
        if (node.isNumber()) {
            return normalizeNumber(node);
        }
        if (node.isTextual() && TEXT_KEYWORDS.contains(key)) {
            return MAPPER.getNodeFactory().textNode(normalizeText(node.textValue()));
        }
        return node;
    }

    /**
     * 数值归一：{@code 100} / {@code 100.0} / {@code 1e2} 是同一个数。
     *
     * <p>Jackson 会分别解析成 {@code IntNode} / {@code DoubleNode}，
     * 直接 {@code toString()} 得到三种不同的写法。这里统一成去尾零的十进制表示。
     */
    private static JsonNode normalizeNumber(JsonNode node) {
        try {
            BigDecimal value = node.decimalValue().stripTrailingZeros();
            if (value.scale() < 0) {
                // 去掉尾零后可能是 1E+2 这种科学计数法写法，展开成 100，
                // 否则 "100" 与 "1E+2" 又会成为两种写法
                value = value.setScale(0);
            }
            return DecimalNode.valueOf(value);
        } catch (ArithmeticException | NumberFormatException e) {
            // 超出 BigDecimal 表示范围的数值（如 1e400）保持原样——宁可比较字节，不可算错
            return node;
        }
    }

    /**
     * 描述性文本归一：换行统一为 LF，去掉首尾空白。
     *
     * <p><b>不动内部空白</b>——描述里的代码块依赖缩进，折叠空白会改变它的可读性，
     * 而可读性正是描述存在的意义。
     */
    public static String normalizeText(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("\r\n", "\n").replace('\r', '\n').strip();
    }
}
