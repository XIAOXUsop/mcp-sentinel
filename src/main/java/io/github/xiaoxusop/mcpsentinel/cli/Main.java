package io.github.xiaoxusop.mcpsentinel.cli;

import io.github.xiaoxusop.mcpsentinel.Baseline;
import io.github.xiaoxusop.mcpsentinel.Change;
import io.github.xiaoxusop.mcpsentinel.ChangeSeverity;
import io.github.xiaoxusop.mcpsentinel.Finding;
import io.github.xiaoxusop.mcpsentinel.SarifWriter;
import io.github.xiaoxusop.mcpsentinel.ScanReport;
import io.github.xiaoxusop.mcpsentinel.SurfaceDiff;
import io.github.xiaoxusop.mcpsentinel.ToolFingerprint;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;
import io.github.xiaoxusop.mcpsentinel.connector.McpConnector;
import io.github.xiaoxusop.mcpsentinel.connector.ServerTarget;
import io.github.xiaoxusop.mcpsentinel.rules.RiskRules;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.Comparator;

/**
 * mcp-sentinel 命令行。
 *
 * <p>三个子命令，对应一条完整的使用闭环：
 * <pre>
 * mcp-sentinel lock --config mcp.json                     # 首次：把当前工具面锁进基线，提交进版本库
 * mcp-sentinel scan --config mcp.json                     # 之后：每次 CI 扫描，与基线对比并查风险
 * mcp-sentinel scan --config mcp.json --accept-changes    # 有意变更被拦下时：批准并写回基线
 * </pre>
 *
 * <p>退出码（可安全用作 CI 门禁）：
 * <ul>
 *   <li>{@code 0} 通过</li>
 *   <li>{@code 1} 用法或配置错误</li>
 *   <li>{@code 2} 连不上目标服务器</li>
 *   <li>{@code 3} 命中达到阈值的风险规则</li>
 *   <li>{@code 4} 工具面有达到阈值的未批准变更</li>
 *   <li>{@code 5} 基线不可用（缺失 / 不是普通文件 / 不可读 / 损坏 / 版本不兼容 / 内容不全）
 *       ——漂移检测这一核心能力没有生效</li>
 *   <li>{@code 6} 输出产物写入失败（{@code --out} / {@code --sarif}）</li>
 * </ul>
 * 风险与漂移同时出现时返回 {@code 4}——漂移是这个工具的核心信号。两种情况都会各自输出
 * 一行 {@code ::error::}，不会因为先判漂移就把风险项的注解吞掉。
 *
 * <p><b>fail-closed</b>：{@code scan} 默认要求基线可用。基线读不到时不会退化成
 * "只做风险扫描然后返回 0"——那会让一次配置事故看起来像一次干净通过。
 * 确实只要静态规则时，用 {@code --risk-only} 显式声明。
 */
public final class Main {

    static final int EXIT_OK = 0;
    static final int EXIT_USAGE = 1;
    static final int EXIT_CONNECT = 2;
    static final int EXIT_FINDINGS = 3;
    static final int EXIT_DRIFT = 4;
    static final int EXIT_BASELINE = 5;
    static final int EXIT_OUTPUT = 6;

    private Main() {
    }

    public static void main(String[] args) {
        // 显式固定输出编码：默认走平台编码，会让中文报告在 UTF-8 环境里变成乱码
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8);
        System.exit(run(args, out, err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0 || "--help".equals(args[0]) || "-h".equals(args[0])) {
            usage(err);
            return args.length == 0 ? EXIT_USAGE : EXIT_OK;
        }
        String command = args[0];
        Path config = null;
        Path baselineFile = Path.of("mcp-sentinel.lock.json");
        boolean baselineExplicit = false;
        Path outFile = null;
        Path sarifFile = null;
        Finding.Severity failOn = Finding.Severity.HIGH;
        ChangeSeverity failOnChange = ChangeSeverity.BREAKING;
        boolean acceptChanges = false;
        boolean riskOnly = false;
        java.time.Duration timeoutOverride = null;

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--config" -> config = Path.of(require(args, ++i, err));
                case "--baseline" -> {
                    baselineFile = Path.of(require(args, ++i, err));
                    baselineExplicit = true;
                }
                case "--out" -> outFile = Path.of(require(args, ++i, err));
                case "--sarif" -> sarifFile = Path.of(require(args, ++i, err));
                case "--accept-changes" -> acceptChanges = true;
                case "--risk-only" -> riskOnly = true;
                case "--timeout" -> {
                    String value = require(args, ++i, err);
                    try {
                        timeoutOverride = java.time.Duration.ofSeconds(
                                Math.max(1, Long.parseLong(value.strip())));
                    } catch (RuntimeException e) {
                        err.println("mcp-sentinel: --timeout 需要秒数，收到 '" + value + "'");
                        return EXIT_USAGE;
                    }
                }
                case "--fail-on" -> {
                    String value = require(args, ++i, err).toUpperCase(Locale.ROOT);
                    try {
                        failOn = Finding.Severity.valueOf(value);
                    } catch (IllegalArgumentException e) {
                        err.println("mcp-sentinel: --fail-on 只能是 HIGH / MEDIUM / LOW");
                        return EXIT_USAGE;
                    }
                }
                case "--fail-on-change" -> {
                    try {
                        failOnChange = ChangeSeverity.parse(require(args, ++i, err));
                    } catch (IllegalArgumentException e) {
                        err.println("mcp-sentinel: " + e.getMessage());
                        return EXIT_USAGE;
                    }
                }
                default -> {
                    err.println("mcp-sentinel: 未知参数 '" + args[i] + "'");
                    return EXIT_USAGE;
                }
            }
        }
        if (config == null) {
            err.println("mcp-sentinel: 必须指定 --config");
            return EXIT_USAGE;
        }
        if (acceptChanges && !"scan".equals(command)) {
            err.println("mcp-sentinel: --accept-changes 只对 scan 有意义");
            return EXIT_USAGE;
        }
        if (riskOnly && !"scan".equals(command)) {
            err.println("mcp-sentinel: --risk-only 只对 scan 有意义");
            return EXIT_USAGE;
        }
        if (riskOnly && acceptChanges) {
            err.println("mcp-sentinel: --risk-only 与 --accept-changes 互斥"
                    + "（前者不做漂移检测，后者要批准漂移）");
            return EXIT_USAGE;
        }
        if (riskOnly && baselineExplicit) {
            err.println("mcp-sentinel: --risk-only 与 --baseline 互斥"
                    + "（显式给了基线文件，就应该做漂移检测）");
            return EXIT_USAGE;
        }

        ServerTarget target;
        try {
            target = ServerTarget.read(config);
        } catch (Exception e) {
            err.println("mcp-sentinel: 读取配置失败: " + e.getMessage());
            return EXIT_USAGE;
        }

        if (timeoutOverride != null) {
            target = target.withTimeout(timeoutOverride);
        }

        // fail-closed：基线是本地文件，先校验再连服务器。已经知道这次扫描给不出漂移结论，
        // 就不必再去启动一个不可信的 MCP 服务器子进程。
        Baseline baseline = null;
        if ("scan".equals(command) && !riskOnly) {
            BaselineLoad loaded = loadBaseline(baselineFile, err);
            if (!loaded.ok()) {
                return EXIT_BASELINE;
            }
            baseline = loaded.baseline();
        }

        McpConnector.Result connection = McpConnector.connect(target);
        if (!connection.ok()) {
            err.println("mcp-sentinel: 连接服务器失败: " + connection.error());
            err.println("  目标: " + target.command() + " " + String.join(" ", target.args()));
            return EXIT_CONNECT;
        }
        ToolSurface surface = connection.surface();

        return switch (command) {
            case "lock" -> doLock(surface, outFile == null ? baselineFile : outFile, out, err);
            case "scan" -> doScan(surface, config, baselineFile, baseline, outFile, sarifFile,
                    failOn, failOnChange, acceptChanges, riskOnly, out, err);
            default -> {
                err.println("mcp-sentinel: 未知命令 '" + command + "'（可用：lock / scan）");
                yield EXIT_USAGE;
            }
        };
    }

    private static int doLock(ToolSurface surface, Path file, PrintStream out, PrintStream err) {
        try {
            Baseline.of(surface).write(file);
        } catch (Exception e) {
            err.println("mcp-sentinel: 写入基线失败: " + e.getMessage());
            return EXIT_USAGE;
        }
        out.println("已锁定工具面基线: " + file.toAbsolutePath());
        out.println("  服务器      : " + surface.serverName());
        out.println("  工具数      : " + surface.tools().size());
        out.println("  工具面指纹  : " + surface.shortFingerprint());
        out.println();
        out.println("请把该文件提交进版本库——工具定义的变化应当像代码变化一样出现在评审里。");
        return EXIT_OK;
    }

    private static int doScan(ToolSurface surface, Path configFile, Path baselineFile,
                              Baseline loadedBaseline, Path outFile, Path sarifFile,
                              Finding.Severity failOn, ChangeSeverity failOnChange,
                              boolean acceptChanges, boolean riskOnly,
                              PrintStream out, PrintStream err) {
        List<Finding> findings = RiskRules.evaluate(surface);
        Baseline baseline = loadedBaseline;
        SurfaceDiff diff = null;

        if (riskOnly) {
            out.println("模式：--risk-only（显式跳过基线比对，本次不检测工具面漂移）");
        } else {
            // 基线已在连接服务器之前校验过；这里只做比对
            diff = baseline.diffAgainst(surface);
        }

        if (acceptChanges) {
            if (baseline == null) {
                err.println("mcp-sentinel: --accept-changes 需要先有一份可读的基线文件");
                return EXIT_USAGE;
            }
            // 批准 = 把当前工具面升级为新的基线，并把这次的变更指纹记下来。
            // 记下来是为了让同一条变更在后续提交里仍然算已批准——审批不该因为
            // "改了别的东西"而失效。指纹含变更后的内容摘要，所以"批准后再悄悄改一次"
            // 会得到不同的指纹，仍然会拦下。
            List<Change> accepted = diff == null ? List.of() : diff.changes();
            try {
                Baseline before = baseline;
                Baseline updated = Baseline.of(surface, mergeAccepted(baseline, diff));
                updated.write(baselineFile);
                out.println("已接受 " + accepted.size() + " 处变更并写回基线: "
                        + baselineFile.toAbsolutePath());
                printAcceptanceSummary(accepted, before, updated, findings, failOn, out);
            } catch (IOException e) {
                err.println("mcp-sentinel: 写回基线失败: " + e.getMessage());
                return EXIT_USAGE;
            }
            baseline = null;
            diff = null;
        }

        ScanReport report = new ScanReport(surface.serverName(), surface.fingerprint(),
                surface.tools().size(), findings, diff);
        String rendered = report.render();
        out.println(rendered);

        boolean outputFailed = false;
        if (outFile != null) {
            // 旧版把 --out 解析出来却在 scan 里从不使用——不报错、不警告、不产生文件
            try {
                if (outFile.getParent() != null) {
                    Files.createDirectories(outFile.getParent());
                }
                Files.writeString(outFile, rendered, StandardCharsets.UTF_8);
                err.println("报告已写出: " + outFile.toAbsolutePath());
            } catch (IOException e) {
                err.println("mcp-sentinel: 写出报告失败: " + e.getMessage());
                outputFailed = true;
            }
        }

        if (sarifFile != null) {
            try {
                // 位置必须落在仓库内真实存在的文件上，否则 GitHub Code Scanning
                // 不会显示这些结果（官方规则 GH1005）。有基线就指向基线并精确到行。
                SarifWriter.write(report, SarifWriter.Source.fromFiles(configFile, baselineFile), sarifFile);
                out.println("SARIF 已写出: " + sarifFile.toAbsolutePath()
                        + "（可上传到 GitHub Code Scanning，发现会以行内注解出现在 PR 上）");
            } catch (Exception e) {
                // 旧版只打一行 stderr 就继续，最终可能以 0 退出。SARIF 是 CI 真正消费的产物，
                // 写不出来等于这次扫描没有结果上传，却报成功。
                err.println("mcp-sentinel: 写出 SARIF 失败: " + e.getMessage());
                outputFailed = true;
            }
        }

        List<Change> blocking = diff == null ? List.of() : diff.blocking(failOnChange);
        boolean hasFindings = report.hasAtLeast(failOn);

        // 两条 ::error:: 都要发——旧版先判漂移就 return，风险项的注解会被吞掉
        if (hasFindings) {
            err.println("::error::存在达到 " + failOn + " 级别的风险项");
        }
        if (!blocking.isEmpty()) {
            err.println("::error::MCP 工具面有 " + blocking.size() + " 处未批准的变更达到 "
                    + failOnChange + " 级别（共 " + diff.totalChanges() + " 处变化）");
        }
        if (outputFailed) {
            err.println("::error::输出产物写入失败，本次扫描结果不完整（CI 拿不到报告/SARIF）");
        }
        if (!blocking.isEmpty()) {
            return EXIT_DRIFT;
        }
        if (hasFindings) {
            return EXIT_FINDINGS;
        }
        return outputFailed ? EXIT_OUTPUT : EXIT_OK;
    }

    /** 基线加载结果：要么可用，要么已经打印了失败原因 */
    private record BaselineLoad(Baseline baseline) {
        boolean ok() {
            return baseline != null;
        }
    }

    /**
     * 读基线，任何一种读不出来的情况都返回失败。
     *
     * <p>刻意<b>不</b>在这里重新生成基线：自动重建会把"基线被换掉了"这件事
     * 变成一次安静的自愈，而基线本身就是"当初批准的是什么"的证据。
     */
    private static BaselineLoad loadBaseline(Path baselineFile, PrintStream err) {
        if (!Files.exists(baselineFile)) {
            err.println("mcp-sentinel: 找不到基线文件 " + baselineFile.toAbsolutePath()
                    + "，无法检测工具面漂移。");
            err.println("  首次使用：运行 `mcp-sentinel lock --config <配置> --out " + baselineFile
                    + "`，并把生成的基线提交进版本库。");
            err.println("  若你确实只想跑静态风险规则、不做漂移检测：显式加 `--risk-only`。");
            return new BaselineLoad(null);
        }
        if (!Files.isRegularFile(baselineFile)) {
            err.println("mcp-sentinel: 基线路径不是普通文件：" + baselineFile.toAbsolutePath()
                    + "（可能是目录、符号链接指向的目标不存在，或权限不足）。");
            return new BaselineLoad(null);
        }
        try {
            return new BaselineLoad(Baseline.read(baselineFile));
        } catch (Exception e) {
            err.println("mcp-sentinel: 基线不可用，漂移检测无法进行：" + e.getMessage());
            err.println("  不会自动重建基线——请人工确认这份文件为何不可读，"
                    + "再决定是否重新运行 `mcp-sentinel lock`。");
            return new BaselineLoad(null);
        }
    }

    /**
     * 把"这次批准了什么"完整打出来。
     *
     * <p>批准动作会改写基线文件，而基线是"当初批准的是什么"的证据。如果只在提交里看到
     * 一个 `mcp-sentinel.lock.json` 的二进制式 diff，评审者实际上没有任何可审的东西——
     * 他看不出被批准的是「加了个可选参数」还是「描述被换成了另一段话」。
     *
     * <p>所以这里把三件事摊开：批准了哪些工具、每条变更的级别与前后摘要、
     * 以及**基线的新指纹**（评审者据此确认"我批准的确实是这一版工具面"）。
     *
     * <p><b>静态风险发现不在批准范围内。</b>它们描述的是当前工具面本身有问题，
     * 而不是"和上次不一样"。批准基线不会、也不该让它们消失——这一点必须说出来，
     * 否则很容易被误以为"批准过就没事了"。
     */
    private static void printAcceptanceSummary(List<Change> accepted, Baseline before, Baseline after,
                                               List<Finding> findings,
                                               Finding.Severity failOn, PrintStream out) {
        Map<String, String> previousFingerprints = new LinkedHashMap<>();
        for (Baseline.ToolEntry entry : before.tools()) {
            previousFingerprints.putIfAbsent(entry.tool().name(), entry.fingerprint());
        }

        out.println();
        out.println("本次批准的变更（写进基线的 acceptedChanges，后续提交里继续算已批准）：");
        if (accepted.isEmpty()) {
            out.println("  （无——工具面与基线一致，这次批准只是把基线指纹刷新了一遍）");
        }
        Map<String, Integer> bySeverity = new TreeMap<>();
        for (Change change : accepted) {
            bySeverity.merge(change.severity().name(), 1, Integer::sum);
            String was = previousFingerprints.getOrDefault(change.toolName(), "-");
            out.println("  [%s] %-28s %-22s %s → %s".formatted(
                    change.severity(), change.id(), change.describe(),
                    shortDigest(was), shortDigest(change.afterDigest())));
            if (!change.detail().isBlank()) {
                out.println("      " + change.detail());
            }
            out.println("      变更指纹 " + change.digest());
        }
        out.println("  按级别统计: " + bySeverity);

        out.println();
        out.println("工具面指纹 : " + shortFingerprint(before) + " → " + shortFingerprint(after));
        out.println("基线文件   : " + after.generatedAt());

        long blocking = findings.stream().filter(f -> f.severity().ordinal() <= failOn.ordinal()).count();
        out.println();
        out.println("静态风险发现**不参与批准**：它们描述的是当前工具面本身有问题，而不是「和上次不一样」。");
        if (findings.isEmpty()) {
            out.println("  本次没有静态风险发现。");
        } else {
            out.println("  本次仍有 " + findings.size() + " 条发现，其中达到 " + failOn + " 级别的有 "
                    + blocking + " 条；批准基线不会让它们消失，需要改工具定义本身：");
            findings.stream()
                    .sorted(Comparator.comparing((Finding f) -> f.severity().ordinal())
                            .thenComparing(Finding::toolName))
                    .limit(10)
                    .forEach(f -> out.println("    " + f.format()));
            if (findings.size() > 10) {
                out.println("    …共 " + findings.size() + " 条，完整清单见报告。");
            }
        }
    }

    private static String shortFingerprint(Baseline baseline) {
        return ToolFingerprint.shortOf(baseline.surfaceFingerprint());
    }

    private static String shortDigest(String digest) {
        if (digest == null || digest.isBlank() || "-".equals(digest)) {
            return "-";
        }
        return digest.substring(0, Math.min(16, digest.length()));
    }

    /** 把这次被批准的变更指纹并入基线原有的已批准集合，按指纹去重 */
    private static List<Baseline.AcceptedChange> mergeAccepted(Baseline baseline, SurfaceDiff diff) {
        Map<String, Baseline.AcceptedChange> merged = new LinkedHashMap<>();
        for (Baseline.AcceptedChange change : baseline.acceptedChanges()) {
            merged.put(change.digest(), change);
        }
        if (diff != null) {
            for (Change change : diff.changes()) {
                merged.putIfAbsent(change.digest(),
                        new Baseline.AcceptedChange(change.id(), change.toolName(), change.digest()));
            }
        }
        return new ArrayList<>(merged.values());
    }

    private static String require(String[] args, int index, PrintStream err) {
        if (index >= args.length) {
            err.println("mcp-sentinel: 参数缺值");
            return "";
        }
        return args[index];
    }

    private static void usage(PrintStream err) {
        err.println("""
                mcp-sentinel - MCP 工具面安全扫描器

                用法:
                  mcp-sentinel lock --config <配置> [--out <基线文件>]
                  mcp-sentinel scan --config <配置> [选项]

                选项:
                  --baseline <文件>        基线的位置（默认 mcp-sentinel.lock.json）
                  --risk-only              只跑静态风险规则，不做漂移检测（显式选择）
                  --out <文件>             把报告另存一份
                  --sarif <文件>           输出 SARIF 2.1.0
                  --fail-on LEVEL          风险规则在哪个级别阻断（HIGH / MEDIUM / LOW，默认 HIGH）
                  --fail-on-change LEVEL   工具面变更在哪个级别阻断
                                           （INFO / BREAKING / DANGEROUS，默认 BREAKING）
                  --accept-changes         批准本次变更并写回基线（有意的迭代走这一步）
                  --timeout N              连接超时秒数（默认取配置里的 timeoutSeconds，否则 20）

                配置（与主流 MCP 客户端格式一致）:
                  { "server": "my-server", "command": "java", "args": ["-jar", "server.jar"] }

                fail-closed:
                  scan 默认要求基线可用。基线缺失 / 不是普通文件 / 不可读 / 损坏 /
                  版本不兼容 / 内容不全时一律退出 5，不会退化成"只做风险扫描然后返回 0"。
                  确实只要静态规则时，用 --risk-only 显式声明。

                它检测什么:
                  · 工具描述里夹带面向模型的指令（tool poisoning / OWASP MCP03）
                  · 零宽字符隐藏指令、超长 base64 载荷
                  · schema 过宽（无参数约束 / additionalProperties / 未约束字符串）
                  · 危险参数名（command / exec / sql …）
                  · 描述自称只读但 schema 含写入语义参数
                  · 工具影子（与既有工具高度相似的定义）、工具名重复
                  · 工具面相对基线的变更（rug pull：名字没变、定义被改写），并按
                    「扩大攻击面 / 破坏调用方 / 纯信息性」三档分级

                退出码: 0 通过 · 1 用法错误 · 2 连接失败 · 3 命中风险 · 4 工具面有未批准变更
                        · 5 基线不可用（漂移检测未生效）· 6 输出产物写入失败
                """);
    }
}
