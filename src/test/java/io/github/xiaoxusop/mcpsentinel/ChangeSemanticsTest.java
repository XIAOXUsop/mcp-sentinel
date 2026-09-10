package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 变更的语义分级。
 *
 * <p>旧模型只有"指纹相等 / 不等"，于是「加了可选参数」「改了描述」「加了必填参数」
 * 三者输出**完全相同**。而它们的处置正好相反：第一个扩大攻击面、第二个是投毒本体、
 * 第三个会打断所有调用方。
 *
 * <p>分级判据与 oasdiff / buf / graphql-inspector **相反**，这是 MCP 特有的：
 * 那三个工具的判据是"请求收窄、响应放宽会破坏客户端"，所以把"描述改了"判为 {@code info}
 * ——Cisco 的 mcpcontract 规则文件里逐字写着
 * {@code rationale: "Descriptions are informational only and don't affect functionality"}。
 * 那对 OpenAPI 文档是对的；对 MCP 是灾难性的，因为**描述就是投放给模型的指令面**。
 */
class ChangeSemanticsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ToolDefinition tool(String name, String description, String schema) {
        return new ToolDefinition(name, description, json(schema));
    }

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 把「基线里的定义」与「当前的定义」比一遍 */
    private static SurfaceDiff diff(ToolDefinition before, ToolDefinition after) {
        Baseline baseline = Baseline.of(ToolSurface.of("srv", List.of(before)));
        return baseline.diffAgainst(ToolSurface.of("srv", List.of(after)));
    }

    private static Change single(ToolDefinition before, ToolDefinition after) {
        SurfaceDiff diff = diff(before, after);
        assertEquals(1, diff.totalChanges(), "应恰好产出一条变更：" + diff.summary());
        return diff.changes().get(0);
    }

    private static final String BASE = """
            {"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}""";

    // ---------- 四个原本分不出来的场景 ----------

    /**
     * 这四个场景在旧模型里输出**完全相同**（都是「修改 1 个：[x]」）。
     * 现在它们必须各自给出自己的变更类型与严重级别。
     */
    @Test
    void theFourScenariosThatUsedToLookIdenticalNowDiffer() {
        String withOptional = """
                {"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer"}},
                 "required":["q"]}""";
        String withRequired = """
                {"type":"object","properties":{"q":{"type":"string"},"to":{"type":"string"}},
                 "required":["q","to"]}""";

        Change optional = single(tool("search", "Searches", BASE), tool("search", "Searches", withOptional));
        Change required = single(tool("search", "Searches", BASE), tool("search", "Searches", withRequired));
        Change description = single(tool("search", "Searches", BASE), tool("search", "Searches better", BASE));
        Change annotations = single(
                new ToolDefinition("search", "", "Searches", json(BASE), null, json("{\"readOnlyHint\":false}")),
                new ToolDefinition("search", "", "Searches", json(BASE), null, json("{\"readOnlyHint\":true}")));

        assertEquals("PARAM_ADDED_OPTIONAL", optional.id());
        assertEquals(ChangeSeverity.DANGEROUS, optional.severity());

        assertEquals("PARAM_ADDED_REQUIRED", required.id());
        assertEquals(ChangeSeverity.BREAKING, required.severity());

        assertEquals("DESCRIPTION_CHANGED", description.id());
        assertEquals(ChangeSeverity.DANGEROUS, description.severity());

        assertEquals("ANNOTATION_READONLY_FLIPPED", annotations.id());
        assertEquals(ChangeSeverity.DANGEROUS, annotations.severity());

        // 四者两两不同——这正是旧模型做不到的
        assertEquals(4, Set.of(optional.id(), required.id(), description.id(), annotations.id()).size());
    }

    // ---------- 分级判据：放宽 = 危险 ----------

    @Test
    void wideningChangesAreDangerous() {
        assertEquals("SCHEMA_OPENED", single(
                tool("t", "T", "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}}}"),
                tool("t", "T", "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}},"
                        + "\"additionalProperties\":true}")).id());

        // enum 放宽
        assertEquals("PARAM_ENUM_WIDENED", single(
                tool("t", "T", "{\"type\":\"object\",\"properties\":{\"m\":{\"enum\":[\"a\",\"b\"]}}}"),
                tool("t", "T", "{\"type\":\"object\",\"properties\":{\"m\":{\"enum\":[\"a\",\"b\",\"c\"]}}}")).id());

        // 去掉约束
        assertEquals("PARAM_CONSTRAINT_REMOVED", single(
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"string\",\"pattern\":\"^a\"}}}"),
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"string\"}}}")).id());

        // 不再必填 —— 调用方可以省略它了，等于少一道约束
        assertEquals("REQUIRED_REMOVED", single(
                tool("t", "T", "{\"properties\":{\"q\":{\"type\":\"string\"}},\"required\":[\"q\"]}"),
                tool("t", "T", "{\"properties\":{\"q\":{\"type\":\"string\"}}}")).id());

        // 参数描述被改写 —— 与顶层描述同理，都是投放给模型的内容
        assertEquals("PARAM_DESCRIPTION_CHANGED", single(
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"string\",\"description\":\"a\"}}}"),
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"string\",\"description\":\"b\"}}}")).id());
    }

    @Test
    void narrowingChangesAreBreaking() {
        assertEquals("PARAM_ENUM_NARROWED", single(
                tool("t", "T", "{\"type\":\"object\",\"properties\":{\"m\":{\"enum\":[\"a\",\"b\",\"c\"]}}}"),
                tool("t", "T", "{\"type\":\"object\",\"properties\":{\"m\":{\"enum\":[\"a\",\"b\"]}}}")).id());

        assertEquals("PARAM_CONSTRAINT_ADDED", single(
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"string\"}}}"),
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"string\",\"maxLength\":10}}}")).id());

        assertEquals("REQUIRED_ADDED", single(
                tool("t", "T", "{\"properties\":{\"q\":{\"type\":\"string\"}}}"),
                tool("t", "T", "{\"properties\":{\"q\":{\"type\":\"string\"}},\"required\":[\"q\"]}")).id());

        assertEquals("PARAM_REMOVED", single(
                tool("t", "T", "{\"properties\":{\"a\":{\"type\":\"string\"},\"b\":{\"type\":\"string\"}}}"),
                tool("t", "T", "{\"properties\":{\"a\":{\"type\":\"string\"}}}")).id());

        // 改名 = 删除 + 新增：两条都要报，不能只报一半
        SurfaceDiff renamed = diff(tool("t", "T", "{\"type\":\"object\"}"),
                tool("other", "T", "{\"type\":\"object\"}"));
        assertTrue(renamed.changes().stream().anyMatch(c -> c.id().equals("TOOL_REMOVED")),
                renamed.summary());
        assertTrue(renamed.changes().stream().anyMatch(c -> c.id().equals("TOOL_ADDED")),
                renamed.summary());
    }

    /** 类型变成 string（最宽的基本类型），或单一类型变成联合类型——都是放宽 */
    @Test
    void typeWideningIsDistinguishedFromTypeChange() {
        assertEquals("PARAM_TYPE_WIDENED", single(
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"integer\"}}}"),
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"string\"}}}")).id());

        assertEquals("PARAM_TYPE_CHANGED", single(
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"integer\"}}}"),
                tool("t", "T", "{\"properties\":{\"p\":{\"type\":\"boolean\"}}}")).id());
    }

    /** 把声明往"更安全"的方向翻是危险方向：客户端会因此少一道确认，而实际行为没变安全 */
    @Test
    void loweringDeclaredRiskIsDangerousAndRaisingItIsNot() {
        Change lowered = single(
                new ToolDefinition("t", "", "T", json("{}"), null, json("{\"destructiveHint\":true}")),
                new ToolDefinition("t", "", "T", json("{}"), null, json("{\"destructiveHint\":false}")));
        assertEquals("ANNOTATION_DESTRUCTIVE_FLIPPED", lowered.id());
        assertEquals(ChangeSeverity.DANGEROUS, lowered.severity());

        Change raised = single(
                new ToolDefinition("t", "", "T", json("{}"), null, json("{\"destructiveHint\":false}")),
                new ToolDefinition("t", "", "T", json("{}"), null, json("{\"destructiveHint\":true}")));
        assertEquals(ChangeSeverity.INFO, raised.severity());
    }

    @Test
    void titleAndOutputSchemaAreGradedDistinctly() {
        Change title = single(
                new ToolDefinition("t", "Old title", "T", json("{}"), null, null),
                new ToolDefinition("t", "New title", "T", json("{}"), null, null));
        assertEquals("TITLE_CHANGED", title.id());
        assertEquals(ChangeSeverity.INFO, title.severity());

        Change output = single(
                new ToolDefinition("t", "", "T", json("{}"), json("{\"type\":\"object\"}"), null),
                new ToolDefinition("t", "", "T", json("{}"), json("{\"type\":\"array\"}"), null));
        assertEquals("OUTPUT_SCHEMA_CHANGED", output.id());
        assertEquals(ChangeSeverity.BREAKING, output.severity());
    }

    /** 新增工具是攻击面——rug pull 最常见的形态就是"多出来一个工具" */
    @Test
    void addedToolIsDangerous() {
        SurfaceDiff diff = Baseline.of(ToolSurface.of("srv", List.of(tool("a", "A", "{}"))))
                .diffAgainst(ToolSurface.of("srv", List.of(tool("a", "A", "{}"), tool("b", "B", "{}"))));

        assertEquals(List.of("b"), diff.added());
        assertEquals(ChangeSeverity.DANGEROUS, diff.changes().get(0).severity());
    }

    // ---------- 变更指纹：跨 commit 稳定，且绑定内容 ----------

    /**
     * 同一条变更，即使换了基线、换了工具面的其他部分，指纹也不变——
     * 这样 commit A 批准过的变更在 commit B 里仍然算已批准，审批不会因为
     * "改了别的东西"而失效。
     */
    @Test
    void changeDigestIsStableAcrossUnrelatedEdits() {
        Change first = single(tool("search", "Searches", BASE), tool("search", "Renamed", BASE));

        ToolSurface other = ToolSurface.of("srv", List.of(
                tool("search", "Searches", BASE), tool("unrelated", "Unrelated", "{}")));
        SurfaceDiff second = Baseline.of(other).diffAgainst(ToolSurface.of("srv", List.of(
                tool("search", "Renamed", BASE), tool("unrelated", "Unrelated", "{}"))));

        assertEquals(1, second.totalChanges());
        assertEquals(first.digest(), second.changes().get(0).digest(),
                "无关工具的存在不该改变这条变更的指纹");
    }

    /**
     * <b>但指纹必须绑定变更后的内容。</b>
     *
     * <p>否则"描述 A→B 被批准"之后再 B→C 会自动继承那次批准——
     * 而"批准之后悄悄再改一次"恰好就是 rug pull 的形态。
     */
    @Test
    void changeDigestIsBoundToTheNewContent() {
        Change toB = single(tool("t", "Alpha", BASE), tool("t", "Beta", BASE));
        Change toC = single(tool("t", "Alpha", BASE), tool("t", "Gamma", BASE));

        assertNotEquals(toB.digest(), toC.digest(),
                "批准了「改成 Beta」不该连带批准「改成 Gamma」");
    }

    // ---------- 审批与阻断 ----------

    @Test
    void approvedChangesAreStillReportedButNoLongerBlock() {
        ToolDefinition before = tool("t", "Alpha", BASE);
        ToolDefinition after = tool("t", "Beta", BASE);

        Baseline plain = Baseline.of(ToolSurface.of("srv", List.of(before)));
        SurfaceDiff blocked = plain.diffAgainst(ToolSurface.of("srv", List.of(after)));
        assertEquals(1, blocked.blocking(ChangeSeverity.BREAKING).size());
        assertFalse(blocked.isClean(), "已批准不等于没变化——报告里仍要看得到");

        Change change = blocked.changes().get(0);
        Baseline withApproval = Baseline.of(ToolSurface.of("srv", List.of(before)),
                List.of(new Baseline.AcceptedChange(change.id(), change.toolName(), change.digest())));
        SurfaceDiff accepted = withApproval.diffAgainst(ToolSurface.of("srv", List.of(after)));

        assertEquals(1, accepted.totalChanges(), "已批准的变更仍然出现在变更集里");
        assertTrue(accepted.isApproved(accepted.changes().get(0)));
        assertTrue(accepted.blocking(ChangeSeverity.BREAKING).isEmpty(), accepted.summary());
        assertTrue(accepted.summary().contains("已批准"), accepted.summary());
    }

    /** 默认阈值之下：只有 INFO 级变更时不阻断 */
    @Test
    void infoOnlyChangesDoNotBlockAtTheDefaultLevel() {
        SurfaceDiff diff = diff(
                new ToolDefinition("t", "Old", "T", json("{}"), null, null),
                new ToolDefinition("t", "New", "T", json("{}"), null, null));

        assertEquals(1, diff.totalChanges());
        assertTrue(diff.blocking(ChangeSeverity.BREAKING).isEmpty(),
                "标题改动不该在默认级别阻断：" + diff.summary());
        assertEquals(1, diff.blocking(ChangeSeverity.INFO).size(),
                "但把阈值调到 INFO 就应该拦下");
    }

    /** 变更集按严重级别降序排列，保证输出稳定可读 */
    @Test
    void changesAreOrderedBySeverity() {
        String before = """
                {"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}""";
        String after = """
                {"type":"object","properties":{"q":{"type":"string"},"extra":{"type":"string"}},
                 "required":["q","extra"]}""";

        SurfaceDiff diff = diff(
                new ToolDefinition("t", "Old title", "Old description", json(before), null, null),
                new ToolDefinition("t", "New title", "New description", json(after), null, null));

        List<ChangeSeverity> severities = diff.sorted().stream().map(Change::severity).toList();
        assertEquals(List.of(ChangeSeverity.DANGEROUS, ChangeSeverity.BREAKING, ChangeSeverity.INFO),
                severities, diff.summary());
    }
}
