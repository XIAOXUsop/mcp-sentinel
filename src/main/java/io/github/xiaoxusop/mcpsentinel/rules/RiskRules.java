package io.github.xiaoxusop.mcpsentinel.rules;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.xiaoxusop.mcpsentinel.Finding;
import io.github.xiaoxusop.mcpsentinel.ToolDefinition;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 工具面的静态风险规则。
 *
 * <p>这些规则针对的是 MCP 特有的攻击面：工具定义本身是**不可信输入**——
 * 它由服务器提供，会进入模型的上下文，而模型会照着它行动。
 * 因此"描述里写了什么"和"schema 允许多宽"都是安全问题，不只是文档质量问题。
 *
 * <p>每条规则都给出**为什么**有风险，而不只是"命中了模式"——安全告警必须可解释，
 * 否则使用者只会学会忽略它。
 */
public final class RiskRules {

    /** 面向模型的指令性措辞：正常工具描述不会命令模型做什么 */
    private static final Pattern HIDDEN_INSTRUCTION = Pattern.compile(
            "(?i)(ignore\\s+(all\\s+)?(previous|prior|above)\\s+instructions?"
                    + "|disregard\\s+(your|all|any)\\s+(previous|prior|instructions?|rules?)"
                    + "|do\\s+not\\s+(tell|mention|inform|reveal|disclose)"
                    + "|don'?t\\s+(tell|mention|inform|reveal|disclose)"
                    + "|without\\s+(telling|informing|asking)\\s+the\\s+user"
                    + "|before\\s+(using|calling)\\s+this\\s+tool,?\\s+(always|first|you\\s+must)"
                    + "|you\\s+are\\s+now|new\\s+instructions?"
                    + "|system\\s*prompt|\\bprompt\\s*injection\\b)");

    /** 零宽字符：用于把指令藏进肉眼看不见的位置 */
    private static final Pattern INVISIBLE = Pattern.compile("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]");

    /** 长 base64 串：可能是被编码的隐藏指令 */
    private static final Pattern BASE64_BLOB = Pattern.compile("\\b[A-Za-z0-9+/]{120,}={0,2}\\b");

    /** 危险参数名：出现这些通常意味着工具能触达执行面 */
    private static final Pattern DANGEROUS_PARAM = Pattern.compile(
            "(?i)^(command|cmd|exec|execute|shell|script|sql|query|path|file|filepath|url|uri|endpoint|host)$");

    private RiskRules() {
    }

    /** 对整份工具面执行全部规则 */
    public static List<Finding> evaluate(ToolSurface surface) {
        List<Finding> findings = new ArrayList<>();
        for (ToolDefinition tool : surface.sorted()) {
            findings.addAll(hiddenInstructions(tool));
            findings.addAll(overbroadSchema(tool));
            findings.addAll(dangerousParameters(tool));
            findings.addAll(descriptionSchemaMismatch(tool));
        }
        findings.addAll(toolShadowing(surface));
        return findings;
    }

    // ---------- R1：描述里夹带面向模型的指令 ----------

    public static List<Finding> hiddenInstructions(ToolDefinition tool) {
        List<Finding> findings = new ArrayList<>();
        String text = tool.searchableText();

        Matcher instructions = HIDDEN_INSTRUCTION.matcher(text);
        if (instructions.find()) {
            findings.add(new Finding("HIDDEN_INSTRUCTION", Finding.Severity.HIGH, tool.name(),
                    "工具定义中含面向模型的指令性措辞。工具描述会被放进模型上下文，"
                            + "这类措辞可诱导模型偏离用户意图执行操作（OWASP MCP03 tool poisoning）",
                    snippet(text, instructions.start(), instructions.end())));
        }

        Matcher invisible = INVISIBLE.matcher(text);
        if (invisible.find()) {
            findings.add(new Finding("INVISIBLE_CHARACTERS", Finding.Severity.HIGH, tool.name(),
                    "定义中含零宽/双向控制字符：正常文本不需要它们，"
                            + "常见用途是把指令藏到人眼看不见的位置",
                    "U+" + Integer.toHexString(text.codePointAt(invisible.start())).toUpperCase(Locale.ROOT)));
        }

        Matcher blob = BASE64_BLOB.matcher(text);
        if (blob.find()) {
            findings.add(new Finding("ENCODED_PAYLOAD", Finding.Severity.MEDIUM, tool.name(),
                    "定义中含超长 base64 串：可能是被编码的隐藏指令或外带数据",
                    snippet(text, blob.start(), Math.min(blob.end(), blob.start() + 40))));
        }
        return findings;
    }

    // ---------- R2：schema 过宽 ----------

    public static List<Finding> overbroadSchema(ToolDefinition tool) {
        List<Finding> findings = new ArrayList<>();
        JsonNode schema = tool.inputSchema();

        if (tool.parameterNames().isEmpty() && !"object".equals(schema.path("type").asText(""))) {
            return findings;
        }
        if (tool.parameterNames().isEmpty()) {
            findings.add(new Finding("SCHEMA_NO_PARAMETERS", Finding.Severity.HIGH, tool.name(),
                    "工具声明了 object 类型的入参却没有任何属性："
                            + "调用方无法预知会被传入什么，也无法对参数做校验",
                    schema.toString()));
            return findings;
        }

        if (schema.path("additionalProperties").asBoolean(false)) {
            findings.add(new Finding("SCHEMA_OPEN_OBJECT", Finding.Severity.MEDIUM, tool.name(),
                    "schema 允许 additionalProperties：未声明的字段会被静默接受，"
                            + "使调用方看到的契约与实际可传内容不一致",
                    "additionalProperties=true"));
        }

        if (tool.requiredParameters().isEmpty() && tool.parameterNames().size() > 3) {
            findings.add(new Finding("SCHEMA_NO_REQUIRED", Finding.Severity.LOW, tool.name(),
                    "有多个参数但没有任何必填约束：模型可能只填一部分就发起调用，"
                            + "导致工具在缺参状态下执行",
                    "parameters=" + tool.parameterNames()));
        }

        for (String parameter : tool.parameterNames()) {
            JsonNode definition = schema.path("properties").path(parameter);
            if (definition.isObject() && "string".equals(definition.path("type").asText(""))
                    && isUnconstrainedString(definition)) {
                findings.add(new Finding("SCHEMA_UNCONSTRAINED_STRING", Finding.Severity.LOW, tool.name(),
                        "字符串参数 " + parameter + " 没有任何取值约束：任意长度任意内容都会被接受",
                        definition.toString()));
            }
        }
        return findings;
    }

    /**
     * 字符串是否完全无约束。
     *
     * <p>{@code format} 也算约束——把它漏掉会误报大量正规工具：
     * {@code {"type":"string","format":"date"}} 的日期参数显然不是"任意内容"。
     * 这个误报来自测试用例，不是凭空设想的。
     */
    private static boolean isUnconstrainedString(JsonNode definition) {
        for (String constraint : new String[]{"enum", "const", "pattern", "format",
                "maxLength", "minLength", "maximum", "minimum"}) {
            if (!definition.path(constraint).isMissingNode()) {
                return false;
            }
        }
        return true;
    }

    // ---------- R3：危险参数名 ----------

    public static List<Finding> dangerousParameters(ToolDefinition tool) {
        List<Finding> findings = new ArrayList<>();
        for (String parameter : tool.parameterNames()) {
            if (DANGEROUS_PARAM.matcher(parameter).matches()) {
                findings.add(new Finding("DANGEROUS_PARAMETER", Finding.Severity.MEDIUM, tool.name(),
                        "参数名 " + parameter + " 指向执行/访问面："
                                + "这类参数一旦被模型或被注入的指令控制，影响范围远超数据读取",
                        parameter));
            }
        }
        return findings;
    }

    // ---------- R4：描述与 schema 语义冲突 ----------

    public static List<Finding> descriptionSchemaMismatch(ToolDefinition tool) {
        String description = tool.description().toLowerCase(Locale.ROOT);
        boolean claimsReadOnly = description.contains("read-only") || description.contains("readonly")
                || description.contains("只读") || description.contains("查询")
                || description.contains("search") || description.contains("retrieve");
        if (!claimsReadOnly) {
            return List.of();
        }
        Set<String> writeish = new LinkedHashSet<>();
        for (String parameter : tool.parameterNames()) {
            String lower = parameter.toLowerCase(Locale.ROOT);
            if (lower.startsWith("set") || lower.startsWith("update") || lower.startsWith("delete")
                    || lower.startsWith("create") || lower.startsWith("write") || lower.startsWith("remove")
                    || lower.equals("value") || lower.equals("content") || lower.equals("payload")) {
                writeish.add(parameter);
            }
        }
        if (writeish.isEmpty()) {
            return List.of();
        }
        return List.of(new Finding("DESCRIPTION_SCHEMA_MISMATCH", Finding.Severity.HIGH, tool.name(),
                "描述自称只读，但 schema 含疑似写入语义的参数 " + writeish
                        + "：调用方会基于描述放行，实际却可能发生变更",
                writeish.toString()));
    }

    // ---------- R5：工具影子 ----------

    public static List<Finding> toolShadowing(ToolSurface surface) {
        List<Finding> findings = new ArrayList<>();
        List<ToolDefinition> tools = surface.sorted();
        for (int i = 0; i < tools.size(); i++) {
            for (int j = i + 1; j < tools.size(); j++) {
                ToolDefinition a = tools.get(i);
                ToolDefinition b = tools.get(j);
                if (namesRelated(a.name(), b.name()) && similar(a.description(), b.description())) {
                    findings.add(new Finding("TOOL_SHADOWING", Finding.Severity.MEDIUM, b.name(),
                            "与工具 " + a.name() + " 的名称相近且描述高度相似："
                                    + "影子工具可以冒充既有工具，把调用引向另一套实现",
                            "a=" + a.name() + " / b=" + b.name()));
                }
            }
        }
        return findings;
    }

    /**
     * 名称是否"有关系"。
     *
     * <p>不能只靠 token 重叠率：影子工具的典型命名是给原工具**加后缀**
     * （{@code read_file} → {@code read_file_v2} / {@code read_file_pro}），
     * 此时 Jaccard 只有 ~0.67，会被阈值挡掉。包含关系才是真正要抓的形态。
     * 这个漏报来自测试用例，不是凭空设想的。
     */
    private static boolean namesRelated(String a, String b) {
        String na = normalizeName(a);
        String nb = normalizeName(b);
        if (na.isEmpty() || nb.isEmpty()) {
            return false;
        }
        // 一个包含另一个（含加后缀/前缀的仿冒形态）
        if (na.contains(nb) || nb.contains(na)) {
            return true;
        }
        // 否则退回较宽松的 token 重叠
        Set<String> sa = tokens(a);
        Set<String> sb = tokens(b);
        Set<String> intersection = new LinkedHashSet<>(sa);
        intersection.retainAll(sb);
        Set<String> union = new LinkedHashSet<>(sa);
        union.addAll(sb);
        return !union.isEmpty() && intersection.size() * 100 / union.size() >= 60;
    }

    private static String normalizeName(String name) {
        return name == null ? "" : name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9\\u4e00-\\u9fff]", "");
    }

    /** 描述高度相似（Jaccard ≥ 70%）——名称相近 + 描述雷同，才构成影子 */
    private static boolean similar(String a, String b) {
        Set<String> sa = tokens(a);
        Set<String> sb = tokens(b);
        if (sa.isEmpty() || sb.isEmpty()) {
            return false;
        }
        Set<String> intersection = new LinkedHashSet<>(sa);
        intersection.retainAll(sb);
        Set<String> union = new LinkedHashSet<>(sa);
        union.addAll(sb);
        return intersection.size() * 100 / union.size() >= 70;
    }

    private static Set<String> tokens(String text) {
        Set<String> tokens = new LinkedHashSet<>();
        if (text == null) {
            return tokens;
        }
        for (String token : text.toLowerCase(Locale.ROOT).split("[^a-z0-9\\u4e00-\\u9fff]+")) {
            if (!token.isBlank()) {
                tokens.add(token);
            }
        }
        return tokens;
    }

    private static String snippet(String text, int start, int end) {
        int from = Math.max(0, start - 20);
        int to = Math.min(text.length(), end + 20);
        return text.substring(from, to).replace('\n', ' ');
    }
}
