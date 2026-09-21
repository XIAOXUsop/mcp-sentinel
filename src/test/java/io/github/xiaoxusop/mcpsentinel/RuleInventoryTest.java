package io.github.xiaoxusop.mcpsentinel;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 对着代码数一遍：**规则有几条、变更类型有几类**，再与 README 对账。
 *
 * <p>为什么值得单独有一个测试：2026-09-22 发现 README 上这两个数**都是错的**——
 *
 * <pre>
 *   规则      : 写 15，实现 16（表里把 UNSAFE_SERVER_NAME 与 UNSAFE_TOOL_NAME 并成了一行）
 *   变更类型  : 写 22，实现 26
 * </pre>
 *
 * <p>它们之所以能错很久：**两处都自洽**——规则表 15 行、正文也写 15，
 * 于是互相印证、肉眼看不出来。只有去数代码才会发现。
 *
 * <p>这个测试因此不查"表长得对不对"，而是**从源码里把标识符抠出来**，
 * 再要求 README 与它逐项一致。多一条规则而忘了写文档、或文档写了代码里没有的规则，
 * 都会红。
 */
class RuleInventoryTest {

    /** 全大写的标识符字面量——规则 ID 与变更类型 ID 都是这个形状。 */
    private static final Pattern IDENTIFIER = Pattern.compile("\"([A-Z][A-Z_]{6,})\"");

    /** README 里那句「共 N 类变更」。 */
    private static final Pattern CHANGE_COUNT = Pattern.compile("共\\s*\\*{0,2}(\\d+)\\*{0,2}\\s*类变更");

    /** 规则表的一行：`| \`RULE_ID\` | ...` */
    private static final Pattern RULE_ROW = Pattern.compile("^\\|\\s*`([A-Z][A-Z_]+)`\\s*\\|");

    private static Path projectRoot() {
        // surefire 的工作目录是模块根（本仓库是单模块），所以相对路径就能到源码
        Path root = Path.of("").toAbsolutePath();
        Path readme = root.resolve("README.md");
        assertTrue(Files.isRegularFile(readme), "找不到 README.md（工作目录 " + root + "）——"
                + "这个测试靠读它来对账，读不到就必须红，而不是跳过");
        return root;
    }

    private static String read(Path path) throws IOException {
        assertTrue(Files.isRegularFile(path), "找不到源文件：" + path
                + "——路径变了就要改这个测试，不能让对账静默失效");
        return Files.readString(path);
    }

    private static Set<String> identifiersIn(String source) {
        Set<String> found = new LinkedHashSet<>();
        Matcher matcher = IDENTIFIER.matcher(source);
        while (matcher.find()) {
            found.add(matcher.group(1));
        }
        return found;
    }

    @Test
    void ruleTableMatchesTheRulesInCode() throws IOException {
        Path root = projectRoot();
        Set<String> inCode = identifiersIn(
                read(root.resolve("src/main/java/io/github/xiaoxusop/mcpsentinel/rules/RiskRules.java")));
        assertFalse(inCode.isEmpty(), "一条规则 ID 都没从 RiskRules 里抠出来——先看正则是不是失效了");

        Set<String> inReadme = new LinkedHashSet<>();
        for (String line : Files.readAllLines(root.resolve("README.md"))) {
            Matcher row = RULE_ROW.matcher(line);
            if (row.find()) {
                inReadme.add(row.group(1));
            }
        }

        assertEquals(inCode.size(), inReadme.size(),
                "README 的规则表与实现里的规则数对不上。代码里有 " + inCode.size() + " 条："
                        + inCode + "；README 表里 " + inReadme.size() + " 条：" + inReadme);
        for (String id : inCode) {
            assertTrue(inReadme.contains(id), "规则 `" + id + "` 在实现里，却不在 README 的规则表里");
        }
    }

    /**
     * README 那句「共 N 类变更」必须等于代码里真实的变更类型数。
     *
     * <p>变更类型散布在 `SchemaDiff`（逐字段比对）与 `Baseline`（工具增删）两处，
     * 所以两个文件都要数。
     */
    @Test
    void changeClassCountInReadmeMatchesTheCode() throws IOException {
        Path root = projectRoot();
        Set<String> changeTypes = identifiersIn(
                read(root.resolve("src/main/java/io/github/xiaoxusop/mcpsentinel/SchemaDiff.java")));
        changeTypes.addAll(identifiersIn(
                read(root.resolve("src/main/java/io/github/xiaoxusop/mcpsentinel/Baseline.java"))));

        // 抠出来的集合里要是混进了别的常量，这条会先炸——
        // 那时人工确认一下是不是真的多了个非变更类型，再决定放宽还是改 README
        assertTrue(changeTypes.size() >= 20,
                "从 SchemaDiff / Baseline 里只抠出 " + changeTypes.size() + " 个标识符，"
                        + "看起来提取规则失效了：" + changeTypes);

        Matcher matcher = CHANGE_COUNT.matcher(Files.readString(root.resolve("README.md")));
        assertTrue(matcher.find(),
                "README 里找不到「共 N 类变更」这句话。这句话被删掉或改了写法时，"
                        + "这个数字就没人对了——要么改回来，要么改这个测试。");
        int claimed = Integer.parseInt(matcher.group(1));

        assertEquals(changeTypes.size(), claimed,
                "README 写「共 " + claimed + " 类变更」，而代码里有 " + changeTypes.size() + " 类：" + changeTypes);
    }
}
