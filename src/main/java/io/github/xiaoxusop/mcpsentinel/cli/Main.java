package io.github.xiaoxusop.mcpsentinel.cli;

import io.github.xiaoxusop.mcpsentinel.Baseline;
import io.github.xiaoxusop.mcpsentinel.Finding;
import io.github.xiaoxusop.mcpsentinel.ScanReport;
import io.github.xiaoxusop.mcpsentinel.SurfaceDiff;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;
import io.github.xiaoxusop.mcpsentinel.connector.McpConnector;
import io.github.xiaoxusop.mcpsentinel.connector.ServerTarget;
import io.github.xiaoxusop.mcpsentinel.rules.RiskRules;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * mcp-sentinel 命令行。
 *
 * <p>两个子命令，对应一条完整的使用闭环：
 * <pre>
 * mcp-sentinel lock --config mcp.json        # 首次：把当前工具面锁进基线，提交进版本库
 * mcp-sentinel scan --config mcp.json        # 之后：每次 CI 扫描，与基线对比并查风险
 * </pre>
 *
 * <p>退出码（可安全用作 CI 门禁）：
 * <ul>
 *   <li>{@code 0} 通过</li>
 *   <li>{@code 1} 用法或配置错误</li>
 *   <li>{@code 2} 连不上目标服务器</li>
 *   <li>{@code 3} 命中达到阈值的风险规则</li>
 *   <li>{@code 4} 工具面与基线不一致</li>
 * </ul>
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
        Finding.Severity failOn = Finding.Severity.HIGH;

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--config" -> config = Path.of(require(args, ++i, err));
                case "--baseline" -> baselineFile = Path.of(require(args, ++i, err));
                case "--out" -> outFile = Path.of(require(args, ++i, err));
                case "--fail-on" -> {
                    String value = require(args, ++i, err).toUpperCase(Locale.ROOT);
                    try {
                        failOn = Finding.Severity.valueOf(value);
                    } catch (IllegalArgumentException e) {
                        err.println("mcp-sentinel: --fail-on 只能是 HIGH / MEDIUM / LOW");
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
            case "scan" -> doScan(surface, baselineFile, failOn, out, err);
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

    private static int doScan(ToolSurface surface, Path baselineFile, Finding.Severity failOn,
                              PrintStream out, PrintStream err) {
        List<Finding> findings = RiskRules.evaluate(surface);
        SurfaceDiff diff = null;
        if (Files.isRegularFile(baselineFile)) {
            try {
                diff = Baseline.read(baselineFile).diffAgainst(surface);
            } catch (Exception e) {
                err.println("mcp-sentinel: 读取基线失败（将只做风险扫描）: " + e.getMessage());
            }
        } else {
            err.println("提示：未找到基线文件 " + baselineFile + "，本次只做静态风险扫描。"
                    + "运行 `mcp-sentinel lock` 生成基线后可同时检测工具面漂移。");
        }

        ScanReport report = new ScanReport(surface.serverName(), surface.fingerprint(),
                surface.tools().size(), findings, diff);
        out.println(report.render());

        if (diff != null && !diff.isClean()) {
            err.println("::error::MCP 工具面与基线不一致（" + diff.totalChanges() + " 处变化）");
            return EXIT_DRIFT;
        }
        if (report.hasAtLeast(failOn)) {
            err.println("::error::存在达到 " + failOn + " 级别的风险项");
            return EXIT_FINDINGS;
        }
        return EXIT_OK;
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
                  mcp-sentinel scan --config <配置> [--baseline <基线文件>] [--fail-on HIGH|MEDIUM|LOW]

                配置（与主流 MCP 客户端格式一致）:
                  { "server": "my-server", "command": "java", "args": ["-jar", "server.jar"] }

                它检测什么:
                  · 工具描述里夹带面向模型的指令（tool poisoning / OWASP MCP03）
                  · 零宽字符隐藏指令、超长 base64 载荷
                  · schema 过宽（无参数约束 / additionalProperties / 未约束字符串）
                  · 危险参数名（command / exec / sql / path …）
                  · 描述自称只读但 schema 含写入语义参数
                  · 工具影子（与既有工具高度相似的定义）
                  · 工具面相对基线的漂移（rug pull：名字没变、定义被改写）

                退出码: 0 通过 · 1 用法错误 · 2 连接失败 · 3 命中风险 · 4 工具面漂移
                """);
    }
}
