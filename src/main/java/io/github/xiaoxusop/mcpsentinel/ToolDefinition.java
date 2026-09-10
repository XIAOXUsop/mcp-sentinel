package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

/**
 * 一个工具的定义：名称 + 标题 + 描述 + 入参 schema + 出参 schema + 注解。
 *
 * <p>这是扫描与指纹的输入单元。之所以不直接用 SDK 的类型，是为了让
 * 指纹与规则成为**不依赖任何 SDK 的纯逻辑**——这样才能离线单测，
 * 也才能在未来换 SDK 版本时不影响检测语义。
 *
 * <p><b>为什么六个字段都要进指纹</b>：实测过——单独翻转 {@code annotations.destructiveHint}、
 * 改 {@code outputSchema}、改 {@code title}，旧版的指纹**完全不变、零 finding、退出码 0**。
 * 而客户端会依据 {@code destructiveHint} 决定是否自动放行、依据 {@code outputSchema}
 * 校验返回值，所以这三者都是攻击面。对比同类工具：Vercel 的 {@code fingerprintTools}
 * 覆盖 title、MCP Hangar 覆盖 outputSchema、mcpward 覆盖 annotations——
 * 六字段全覆盖是把三者都补上。
 */
public record ToolDefinition(String name, String title, String description,
                             JsonNode inputSchema, JsonNode outputSchema, JsonNode annotations) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public ToolDefinition {
        name = name == null ? "" : name;
        title = title == null ? "" : title;
        description = description == null ? "" : description;
        inputSchema = inputSchema == null ? MAPPER.createObjectNode() : inputSchema;
        outputSchema = outputSchema == null ? MAPPER.createObjectNode() : outputSchema;
        annotations = annotations == null ? MAPPER.createObjectNode() : annotations;
    }

    /** 只要名称、描述与入参的简写（绝大多数调用点用这个） */
    public ToolDefinition(String name, String description, JsonNode inputSchema) {
        this(name, "", description, inputSchema, null, null);
    }

    /**
     * 规范化后的完整形态。指纹对**它**求哈希。
     *
     * <p>走 {@link SchemaCanonicalizer} 而不是简单按键名排序——语义等价的定义必须得到同一个指纹，
     * 否则会因为服务端的字段重排而产生大量假变更。
     */
    public ObjectNode toJson() {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("name", name);
        root.put("title", SchemaCanonicalizer.normalizeText(title));
        root.put("description", SchemaCanonicalizer.normalizeText(description));
        root.set("inputSchema", SchemaCanonicalizer.canonicalize(inputSchema));
        root.set("outputSchema", SchemaCanonicalizer.canonicalize(outputSchema));
        root.set("annotations", SchemaCanonicalizer.canonicalize(annotations));
        return root;
    }

    public String canonicalForm() {
        return toJson().toString();
    }

    /** 从基线文件里读回 */
    public static ToolDefinition fromJson(JsonNode node) {
        return new ToolDefinition(
                node.path("name").asText(""),
                node.path("title").asText(""),
                node.path("description").asText(""),
                node.path("inputSchema"),
                node.path("outputSchema"),
                node.path("annotations"));
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

    /**
     * 描述与 schema 拼成的可搜索文本，供规则扫描。
     *
     * <p><b>刻意用原文而不是规范化后的形态</b>：规则要看得到零宽字符、控制字符这类
     * 规范化会抹掉的痕迹。规范化只服务于指纹，两者用途不同，不能合并成一个。
     */
    public String searchableText() {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append('\n').append(title).append('\n').append(description).append('\n');
        sb.append(inputSchema.toPrettyString()).append('\n');
        sb.append(outputSchema.toPrettyString()).append('\n');
        sb.append(annotations.toPrettyString());
        return sb.toString();
    }
}
