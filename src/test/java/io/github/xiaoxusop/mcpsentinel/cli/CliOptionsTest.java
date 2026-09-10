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
    void unreadableConfigIsAUsageError(@TempDir Path dir) {
        Invocation result = invoke("scan", "--config", dir.resolve("nope.json").toString());

        assertEquals(1, result.code());
        assertTrue(result.err().contains("读取配置失败"), result.err());
    }

    /** 连不上目标服务器是独立退出码，脚本才能把它与"用法错"分开处理 */
    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    void unreachableServerExitsWithTwo(@TempDir Path dir) throws Exception {
        Path file = config(dir, """
                {"server": "broken", "command": "definitely-not-a-real-command-xyz", "args": []}""");

        Invocation result = invoke("scan", "--config", file.toString());

        assertEquals(2, result.code(), result.out() + result.err());
        assertTrue(result.err().contains("连接服务器失败"), result.err());
        // 失败时要给出可读诊断：哪个命令、什么错误——而不是甩一段堆栈
        assertTrue(result.err().contains("definitely-not-a-real-command-xyz"), result.err());
        assertFalse(result.err().contains("\tat "), result.err());
    }
}
