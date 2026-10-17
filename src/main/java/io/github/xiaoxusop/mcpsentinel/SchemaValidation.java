package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashSet;
import java.util.Set;

/** Structural validation of the keywords we interpret; never follows remote references. */
public final class SchemaValidation {
    private static final Set<String> TYPES = Set.of("null", "boolean", "object", "array", "number", "string", "integer");
    private static final Set<String> MAPS = Set.of("properties", "patternProperties", "$defs", "definitions", "dependentSchemas");
    private static final Set<String> SCHEMAS = Set.of("additionalProperties", "unevaluatedProperties", "unevaluatedItems",
            "not", "if", "then", "else", "contains", "propertyNames", "additionalItems", "contentSchema");
    private static final Set<String> ARRAYS = Set.of("allOf", "anyOf", "oneOf", "prefixItems");
    private static final Set<String> COUNTS = Set.of("minLength", "maxLength", "minItems", "maxItems",
            "minProperties", "maxProperties", "minContains", "maxContains");
    private static final Set<String> TEXT = Set.of("title", "description", "pattern", "format", "$schema", "$id",
            "$ref", "$dynamicRef", "$recursiveRef", "$anchor", "$dynamicAnchor", "$comment", "contentEncoding", "contentMediaType");

    private SchemaValidation() { }

    public static void validate(JsonNode schema) {
        validate(schema, "", 0);
    }

    private static void validate(JsonNode schema, String path, int depth) {
        if (depth > SchemaCanonicalizer.MAX_DEPTH) invalid(path, "Schema 嵌套超过安全上限");
        if (schema == null || (!schema.isObject() && !schema.isBoolean())) invalid(path, "必须为 Schema 对象或布尔值");
        if (schema.isBoolean()) return;
        schema.fields().forEachRemaining(field -> {
            String key = field.getKey(); JsonNode value = field.getValue(); String child = path + "/" + pointer(key);
            if (MAPS.contains(key)) {
                object(value, child);
                value.fields().forEachRemaining(entry -> validate(entry.getValue(), child + "/" + pointer(entry.getKey()), depth + 2));
            } else if (SCHEMAS.contains(key)) {
                validate(value, child, depth + 1);
            } else if (ARRAYS.contains(key) || ("items".equals(key) && value.isArray())) {
                // Tuple-form items is retained for existing draft-07 configurations.
                if (!value.isArray() || value.isEmpty()) invalid(child, "必须为非空 Schema 数组");
                for (int i = 0; i < value.size(); i++) validate(value.get(i), child + "/" + i, depth + 2);
            } else if ("items".equals(key)) {
                validate(value, child, depth + 1);
            } else if ("required".equals(key)) {
                strings(value, child, false, false);
            } else if ("type".equals(key)) {
                if (value.isTextual()) {
                    if (!TYPES.contains(value.textValue())) invalid(child, "不是受支持的 JSON 类型名称");
                } else strings(value, child, true, true);
            } else if ("dependentRequired".equals(key)) {
                object(value, child);
                value.fields().forEachRemaining(entry -> strings(entry.getValue(), child + "/" + pointer(entry.getKey()), false, false));
            } else if ("dependencies".equals(key)) {
                object(value, child);
                value.fields().forEachRemaining(entry -> {
                    String dependency = child + "/" + pointer(entry.getKey());
                    if (entry.getValue().isArray()) strings(entry.getValue(), dependency, false, false);
                    else validate(entry.getValue(), dependency, depth + 2);
                });
            } else if ("enum".equals(key) || "examples".equals(key)) {
                if (!value.isArray()) invalid(child, "必须为数组");
                // Values are instances, including nested business keys and arbitrary arrays.
            } else if (TEXT.contains(key)) {
                if (!value.isTextual()) invalid(child, "必须为字符串");
            } else if (COUNTS.contains(key)) {
                if (!value.isNumber() || value.decimalValue().signum() < 0
                        || value.decimalValue().stripTrailingZeros().scale() > 0) invalid(child, "必须为非负整数");
            } else if (Set.of("minimum", "maximum", "multipleOf").contains(key)) {
                if (!value.isNumber() || ("multipleOf".equals(key) && value.decimalValue().signum() <= 0))
                    invalid(child, "必须为数值，multipleOf 还必须大于零");
            } else if (Set.of("uniqueItems", "readOnly", "writeOnly", "deprecated").contains(key)) {
                if (!value.isBoolean()) invalid(child, "必须为布尔值");
            }
            // const/default and unknown extensions are instances, not Schema positions.
        });
    }

    private static void strings(JsonNode value, String path, boolean nonempty, boolean types) {
        if (!value.isArray() || (nonempty && value.isEmpty())) invalid(path, "必须为" + (nonempty ? "非空" : "") + "字符串数组");
        Set<String> seen = new HashSet<>();
        for (JsonNode entry : value) {
            if (!entry.isTextual()) invalid(path, "数组条目必须为字符串");
            if (!seen.add(entry.textValue())) invalid(path, "数组不能包含重复条目");
            if (types && !TYPES.contains(entry.textValue())) invalid(path, "不是受支持的 JSON 类型名称");
        }
    }

    private static void object(JsonNode value, String path) {
        if (!value.isObject()) invalid(path, "必须为对象");
    }

    private static String pointer(String key) { return key.replace("~", "~0").replace("/", "~1"); }
    private static void invalid(String path, String reason) {
        // Report a location and a controlled reason, never echo the offending value.
        throw new IllegalArgumentException("无效 Schema " + (path.isEmpty() ? "/" : path) + ": " + reason);
    }
}
