package io.github.xiaoxusop.mcpsentinel.cli;

import io.github.xiaoxusop.mcpsentinel.Baseline;
import io.github.xiaoxusop.mcpsentinel.Change;
import io.github.xiaoxusop.mcpsentinel.ChangeSeverity;
import io.github.xiaoxusop.mcpsentinel.Finding;
import io.github.xiaoxusop.mcpsentinel.SarifWriter;
import io.github.xiaoxusop.mcpsentinel.ScanReport;
import io.github.xiaoxusop.mcpsentinel.SurfaceDiff;
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
 * </ul>
 * 两者同时出现时返回 {@code 4}——漂移是这个工具的核心信号。两种情况都会各自输出
 * 一行 {@code ::error::}，不会因为先判漂移就把风险项的注解吞掉。
 */
public final class Main {

    static final int EXIT_OK = 0;
    static final int EXIT_USAGE = 1;
    static final int EXIT_CONNECT = 2;
    static final int EXIT_FINDINGS = 3;
    static final int EXIT_DRIFT = 4;

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
        Path outFile = null;
        Path sarifFile = null;
        Finding.Severity failOn = Finding.Severity.HIGH;
        ChangeSeverity failOnChange = ChangeSeverity.BREAKING;
        boolean acceptChanges = false;

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--config" -> config = Path.of(require(args, ++i, err));
                case "--baseline" -> baselineFile = Path.of(require(args, ++i, err));
                case "--out" -> outFile = Path.of(require(args, ++i, err));
                case "--sarif" -> sarifFile = Path.of(require(args, ++i, err));
                case "--accept-changes" -> acceptChanges = true;
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

        ServerTarget target;
        try {
            target = ServerTarget.read(config);
        } catch (Exception e) {
            err.println("mcp-sentinel: 读取配置失败: " + e.getMessage());
            return EXIT_USAGE;
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
            case "scan" -> doScan(surface, config, baselineFile, outFile, sarifFile,
                    failOn, failOnChange, acceptChanges, out, err);
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
                              Path outFile, Path sarifFile,
                              Finding.Severity failOn, ChangeSeverity failOnChange,
                              boolean acceptChanges, PrintStream out, PrintStream err) {
        List<Finding> findings = RiskRules.evaluate(surface);
        Baseline baseline = null;
        SurfaceDiff diff = null;
        if (Files.isRegularFile(baselineFile)) {
            try {
                baseline = Baseline.read(baselineFile);
                diff = baseline.diffAgainst(surface);
            } catch (Exception e) {
                err.println("mcp-sentinel: 读取基线失败（将只做风险扫描）: " + e.getMessage());
            }
        } else {
            err.println("提示：未找到基线文件 " + baselineFile + "，本次只做静态风险扫描。"
                    + "运行 `mcp-sentinel lock` 生成基线后可同时检测工具面漂移。");
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
            try {
                Baseline updated = Baseline.of(surface, mergeAccepted(baseline, diff));
                updated.write(baselineFile);
                out.println("已接受 " + (diff == null ? 0 : diff.totalChanges())
                        + " 处变更并写回基线: " + baselineFile.toAbsolutePath());
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
                err.println("mcp-sentinel: 写出 SARIF 失败: " + e.getMessage());
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
        if (!blocking.isEmpty()) {
            return EXIT_DRIFT;
        }
        return hasFindings ? EXIT_FINDINGS : EXIT_OK;
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
                  --out <文件>             把报告另存一份
                  --sarif <文件>           输出 SARIF 2.1.0
                  --fail-on LEVEL          风险规则在哪个级别阻断（HIGH / MEDIUM / LOW，默认 HIGH）
                  --fail-on-change LEVEL   工具面变更在哪个级别阻断
                                           （INFO / BREAKING / DANGEROUS，默认 BREAKING）
                  --accept-changes         批准本次变更并写回基线（有意的迭代走这一步）

                配置（与主流 MCP 客户端格式一致）:
                  { "server": "my-server", "command": "java", "args": ["-jar", "server.jar"] }

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
                """);
    }
}
