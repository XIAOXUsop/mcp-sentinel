package io.github.xiaoxusop.mcpsentinel.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 命令行的选项与退出码。
 *
 * <p>退出码是这个工具被集成进流水线时**唯一被消费的东西**——而它此前完全没有单测，
 * 唯一的验证是 CI 里那句 shell 冒烟（只覆盖了 scan 返回 3 这一种情况）。
 */
class CliOptionsTest {

    private record Invocation(int code, String out, String err) {
    }

    private static Invocation invoke(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = Main.run(args,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
        return new Invocation(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static Path config(Path dir, String json) throws Exception {
        Path file = dir.resolve("mcp.json");
        Files.writeString(file, json);
        return file;
    }

    @Test
    void noArgumentsPrintsUsageAndFails() {
        Invocation result = invoke();

        assertEquals(1, result.code());
        assertTrue(result.err().contains("用法"), result.err());
    }

    @Test
    void helpExitsZero() {
        assertEquals(0, invoke("--help").code());
        assertEquals(0, invoke("-h").code());
    }

    @Test
    void missingConfigIsAUsageError() {
        Invocation result = invoke("scan");

        assertEquals(1, result.code());
        assertTrue(result.err().contains("--config"), result.err());
    }

    @Test
    void unknownOptionAndCommandAreUsageErrors() {
        assertEquals(1, invoke("scan", "--bogus").code());
        assertEquals(1, invoke("frobnicate", "--config", "x.json").code());
    }

    @Test
    void invalidOptionValuesAreUsageErrors() {
        assertEquals(1, invoke("scan", "--config", "x.json", "--fail-on", "URGENT").code());
        assertEquals(1, invoke("scan", "--config", "x.json", "--fail-on-change", "URGENT").code());
        assertEquals(1, invoke("scan", "--config", "x.json", "--timeout", "abc").code());
    }

    /** {@code --accept-changes} 只对 scan 有意义，写在别的子命令上要说清楚 */
    @Test
    void acceptChangesIsRejectedOnOtherSubcommands() {
        Invocation result = invoke("lock", "--config", "x.json", "--accept-changes");

        assertEquals(1, result.code());
        assertTrue(result.err().contains("--accept-changes"), result.err());
    }

    @Test
    void riskOnlyIsRejectedOnOtherSubcommands() {
        Invocation result = invoke("lock", "--config", "x.json", "--risk-only");

        assertEquals(1, result.code());
        assertTrue(result.err().contains("--risk-only"), result.err());
    }

    /** --risk-only 说"不做漂移检测"，--baseline 说"拿这个基线做漂移检测"，两者不能同时成立 */
    @Test
    void riskOnlyConflictsWithBaselineAndAcceptChanges(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server": "s", "command": "definitely-not-a-real-command-xyz", "args": []}""");

        assertEquals(1, invoke("scan", "--config", file.toString(),
                "--risk-only", "--baseline", dir.resolve("b.json").toString()).code());
        assertEquals(1, invoke("scan", "--config", file.toString(),
                "--risk-only", "--accept-changes").code());
    }

    @Test
    void unreadableConfigIsAUsageError(@TempDir Path dir) {
        Invocation result = invoke("scan", "--config", dir.resolve("nope.json").toString());

        assertEquals(1, result.code());
        assertTrue(result.err().contains("读取配置失败"), result.err());
    }

    // ---------- fail-closed：基线读不到就不能装作通过 ----------

    /**
     * 基线读不到的每一种情形都必须退出 5。
     *
     * <p>旧版在这里只打一行提示就继续，最后返回 0——一次漏拷的 lock 文件会表现为
     * 一次干净通过，而门禁实际上什么都没守。这类"能力静默失效"是安全工具最坏的失败方式：
     * 它比报错更危险，因为没有人会去修一个显示绿色的门禁。
     *
     * <p>基线是本地文件，校验发生在连接服务器之前，所以这里不需要真的起 MCP 服务器
     * （配置里的 command 是假的也不会被用到）。
     */
    @Test
    void unusableBaselineAlwaysExitsFive(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server": "s", "command": "definitely-not-a-real-command-xyz", "args": []}""");

        record Case(String label, String expectedInMessage, Path baseline) {
        }
        Path missing = dir.resolve("missing.lock.json");

        Path corrupt = dir.resolve("corrupt.lock.json");
        Files.writeString(corrupt, "{ this is not json");

        Path wrongSchema = dir.resolve("wrong-schema.lock.json");
        Files.writeString(wrongSchema, """
                {"version": 2, "schemaVersion": 99999, "server": "s", "tools": []}""");

        Path noTools = dir.resolve("no-tools.lock.json");
        Files.writeString(noTools, """
                {"version": 2, "schemaVersion": %d, "server": "s", "surfaceFingerprint": "abc"}"""
                .formatted(SCHEMA_VERSION));

        Path toolWithoutFingerprint = dir.resolve("incomplete.lock.json");
        Files.writeString(toolWithoutFingerprint, """
                {"version": 2, "schemaVersion": %d, "server": "s", "surfaceFingerprint": "abc",
                 "tools": [{"name": "lookup", "description": "x"}]}""".formatted(SCHEMA_VERSION));

        for (Case item : java.util.List.of(
                new Case("基线不存在", "找不到基线文件", missing),
                new Case("基线 JSON 损坏", "基线不可用", corrupt),
                new Case("schemaVersion 不兼容", "基线不可用", wrongSchema),
                new Case("内容缺少 tools", "基线不可用", noTools),
                new Case("工具条目缺 fingerprint", "基线不可用", toolWithoutFingerprint),
                new Case("基线路径是目录", "不是普通文件", dir))) {
            Invocation result = invoke("scan", "--config", file.toString(),
                    "--baseline", item.baseline().toString());

            assertEquals(5, result.code(), item.label() + " 应退出 5。stdout=" + result.out()
                    + " stderr=" + result.err());
            assertTrue(result.err().contains(item.expectedInMessage()),
                    item.label() + " 的诊断信息应说明原因，实际：" + result.err());
        }
    }

    /** 失败时要说清楚怎么恢复，而且恢复方式绝不能是"自动重建基线" */
    @Test
    void baselineFailureTellsYouHowToRecoverWithoutRebuildingSilently(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server": "s", "command": "definitely-not-a-real-command-xyz", "args": []}""");

        Invocation result = invoke("scan", "--config", file.toString(),
                "--baseline", dir.resolve("missing.lock.json").toString());

        assertEquals(5, result.code(), result.err());
        assertTrue(result.err().contains("lock"), "应指引先运行 lock：" + result.err());
        assertTrue(result.err().contains("--risk-only"), "应给出显式降级的选项：" + result.err());
        assertFalse(result.err().contains("已生成"), "不该自动重建基线：" + result.err());
    }

    /**
     * {@code --risk-only} 是唯一允许没有基线就继续的方式，而且它必须真的跳过基线检查。
     *
     * <p>命令一路走到连接阶段（退出 2）就证明它没有卡在基线校验上——若还在做漂移检测，
     * 这里会因为缺基线退出 5。
     */
    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    void riskOnlyRunsWithoutAnyBaseline(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server": "s", "command": "definitely-not-a-real-command-xyz", "args": []}""");

        Invocation result = invoke("scan", "--config", file.toString(), "--risk-only");

        assertEquals(2, result.code(), result.out() + result.err());
        assertTrue(result.err().contains("连接服务器失败"), result.err());
        assertFalse(result.err().contains("找不到基线文件"), result.err());
    }

    /** 当前规范化规则版本，供构造基线夹具使用 */
    private static final int SCHEMA_VERSION =
            io.github.xiaoxusop.mcpsentinel.SchemaCanonicalizer.VERSION;

    /** 连不上目标服务器是独立退出码，脚本才能把它与"用法错"分开处理 */
    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    void unreachableServerExitsWithTwo(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server": "broken", "command": "definitely-not-a-real-command-xyz", "args": []}""");

        // --risk-only：本用例验证的是连接失败，不该被 fail-closed 的基线检查先拦下
        Invocation result = invoke("scan", "--config", file.toString(), "--risk-only");

        assertEquals(2, result.code(), result.out() + result.err());
        assertTrue(result.err().contains("连接服务器失败"), result.err());
        // 失败时要给出可读诊断：哪个命令、什么错误——而不是甩一段堆栈
        assertTrue(result.err().contains("definitely-not-a-real-command-xyz"), result.err());
        assertFalse(result.err().contains("\tat "), result.err());
    }

    // ---------- Streamable HTTP 的退出码 ----------

    /** 连不上的 HTTP 端点与连不上的 stdio 命令是同一类问题，退出码也该一样 */
    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    void unreachableHttpEndpointExitsWithTwo(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server":"remote","transport":"streamable-http","url":"http://127.0.0.1:1/mcp"}""");

        Invocation result = invoke("scan", "--config", file.toString(), "--risk-only");

        assertEquals(2, result.code(), result.out() + result.err());
        assertTrue(result.err().contains("连接服务器失败"), result.err());
        // 诊断里要给的是 URL，而不是 stdio 的 command/args（那种情况下是空的）
        assertTrue(result.err().contains("127.0.0.1:1"), result.err());
    }

    /**
     * 请求头引用了不存在的环境变量是**配置**错误，不是连接错误。
     *
     * <p>归到"连不上服务器"会把人引到网络排查上去，而真正的原因是自己变量名写错了。
     */
    @Test
    void missingHeaderEnvironmentVariableIsAConfigError(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server":"remote","transport":"streamable-http","url":"http://127.0.0.1:1/mcp",
                 "headers":{"Authorization":"Bearer ${MCP_SENTINEL_DEFINITELY_UNSET}"}}""");

        Invocation result = invoke("scan", "--config", file.toString(), "--risk-only");

        assertEquals(1, result.code(), result.out() + result.err());
        assertTrue(result.err().contains("配置错误"), result.err());
        assertTrue(result.err().contains("MCP_SENTINEL_DEFINITELY_UNSET"), result.err());
        assertFalse(result.err().contains("连接服务器失败"), result.err());
    }

    /** http 传输却把 url 写错/漏写时，配置解析阶段就要报出来 */
    @Test
    void httpWithoutUrlIsAConfigError(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server":"remote","transport":"streamable-http","command":"java"}""");

        Invocation result = invoke("scan", "--config", file.toString(), "--risk-only");

        assertEquals(1, result.code(), result.out() + result.err());
        assertTrue(result.err().contains("url"), result.err());
    }

    @Test
    void unknownTransportIsAConfigError(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json");
        Files.writeString(config, """
                {"server":"s","transport":"carrier-pigeon","url":"http://x/mcp"}""");

        Invocation result = invoke("scan", "--config", config.toString(), "--risk-only");

        assertEquals(1, result.code(), result.out() + result.err());
        assertTrue(result.err().contains("stdio"), result.err());
    }
}
