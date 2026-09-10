package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 一个工具的定义：名称 + 描述 + 入参 schema。
 *
 * <p>这是扫描与指纹的输入单元。之所以不直接用 SDK 的类型，是为了让
 * 指纹与规则成为**不依赖任何 SDK 的纯逻辑**——这样才能离线单测，
 * 也才能在未来换 SDK 版本时不影响检测语义。
 */
public record ToolDefinition(String name, String description, JsonNode inputSchema) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public ToolDefinition {
        name = name == null ? "" : name;
        description = description == null ? "" : description;
        inputSchema = inputSchema == null ? MAPPER.createObjectNode() : inputSchema;
    }

    /**
     * 规范化 JSON：递归按键名排序。
     *
     * <p>为什么必须规范化：MCP 服务器重新序列化时键序可能变化，若直接对原始 JSON 求哈希，
     * 会产出大量**假变更**，让基线对比失去意义。规范化后，"内容变了"才是真的变了。
     */
    public String canonicalForm() {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("name", name);
        root.put("description", description);
        root.set("inputSchema", canonicalize(inputSchema));
        return root.toString();
    }

    private static JsonNode canonicalize(JsonNode node) {
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
            sorted.forEach((key, value) -> result.set(key, canonicalize(value)));
            return result;
        }
        if (node.isArray()) {
            var result = MAPPER.createArrayNode();
            node.forEach(element -> result.add(canonicalize(element)));
            return result;
        }
        return node;
    }

    /** schema 中声明的全部参数名（顶层 properties） */
    public List<String> parameterNames() {
        List<String> names = new ArrayList<>();
        JsonNode properties = inputSchema.path("properties");
        if (properties.isObject()) {
            properties.fieldNames().forEachRemaining(names::add);
        }
        return names;
    }

    /** schema 中声明为必填的参数名 */
    public List<String> requiredParameters() {
        List<String> names = new ArrayList<>();
        JsonNode required = inputSchema.path("required");
        if (required.isArray()) {
            required.forEach(node -> names.add(node.asText()));
        }
        return names;
    }

    /** 描述与 schema 拼成的可搜索文本，供规则扫描 */
    public String searchableText() {
        return name + "\n" + description + "\n" + inputSchema.toPrettyString();
    }
}
