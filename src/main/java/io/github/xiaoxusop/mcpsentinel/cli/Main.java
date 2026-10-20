package io.github.xiaoxusop.mcpsentinel.cli;

import io.github.xiaoxusop.mcpsentinel.Baseline;
import io.github.xiaoxusop.mcpsentinel.Change;
import io.github.xiaoxusop.mcpsentinel.ChangeSeverity;
import io.github.xiaoxusop.mcpsentinel.Finding;
import io.github.xiaoxusop.mcpsentinel.Sanitizer;
import io.github.xiaoxusop.mcpsentinel.SarifWriter;
import io.github.xiaoxusop.mcpsentinel.ScanReport;
import io.github.xiaoxusop.mcpsentinel.ScanError;
import io.github.xiaoxusop.mcpsentinel.SurfaceDiff;
import io.github.xiaoxusop.mcpsentinel.SurfaceSnapshot;
import io.github.xiaoxusop.mcpsentinel.ToolFingerprint;
import io.github.xiaoxusop.mcpsentinel.ToolSurface;
import io.github.xiaoxusop.mcpsentinel.Version;
import io.github.xiaoxusop.mcpsentinel.AtomicFiles;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * mcp-sentinel 命令行。
 *
 * <p>核心子命令：
 * <pre>
 * mcp-sentinel lock --config mcp.json                        # 首次：锁定工具面基线并提交进版本库
 * mcp-sentinel scan --config mcp.json [--json report.json]   # CI：与可信基线对比并查静态风险
 * mcp-sentinel scan --config mcp.json --accept-changes       # 审批：接受有意的工具面变更并写回基线
 * mcp-sentinel snapshot --config mcp.json --out snap.json    # 离线：保存工具面快照（支持 --redact）
 * mcp-sentinel scan --snapshot snap.json --baseline ...      # 离线：不启动服务复跑扫描与比对
 * mcp-sentinel import-config --config claude_desktop.json    # 导入：从 mcpServers 配置提取标准化目标
 * </pre>
 */
public final class Main {

    static final int EXIT_OK = 0;
    static final int EXIT_USAGE = 1;
    static final int EXIT_CONNECT = 2;
    static final int EXIT_FINDINGS = 3;
    static final int EXIT_DRIFT = 4;
    static final int EXIT_BASELINE = 5;
    static final int EXIT_OUTPUT = 6;

    private static final Set<String> COMMANDS = Set.of("lock", "scan", "snapshot", "import-config");
    private static final ObjectMapper JSON = new ObjectMapper();

    private record ReportItem(ScanReport report, Path source, Path baseline, int code, boolean complete) { }
    private static final class Reports {
        final List<ReportItem> items = new ArrayList<>();
        final List<ScanError> inputErrors = new ArrayList<>();
        void failed(ServerTarget target, Path source, Path baseline, int code, String phase, String message) {
            failed(new ScanReport(target.serverName(), "", 0, List.of(), null, "", target.identity()),
                    source, baseline, code, false, phase, target.redactDiagnostic(message));
        }
        void failed(ScanReport report, Path source, Path baseline, int code, boolean complete, String phase, String message) {
            items.add(new ReportItem(report.withErrors(List.of(new ScanError(category(code), phase, message))),
                    source, baseline, code, complete));
        }
    }

    private Main() {
    }

    public static void main(String[] args) {
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8);
        System.exit(run(args, out, err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        Reports reports = new Reports();
        int code;
        try {
            code = runInternal(args, out, err, reports);
        } catch (IllegalArgumentException e) {
            err.println("mcp-sentinel: 输入无效: " + Sanitizer.forReport(e.getMessage(), 200));
            reports.inputErrors.add(new ScanError(category(EXIT_USAGE), "INPUT_VALIDATION", e.getMessage()));
            code = EXIT_USAGE;
        }
        if (args.length == 0 || !"scan".equals(args[0])) return code;
        return writeReports(args, reports, code, out, err);
    }

    private static int runInternal(String[] args, PrintStream out, PrintStream err, Reports reports) {
        if (args.length > 0 && ("--version".equals(args[0]) || "-V".equals(args[0]))) {
            out.println("mcp-sentinel " + Version.value());
            return EXIT_OK;
        }
        if (args.length == 0 || "--help".equals(args[0]) || "-h".equals(args[0])) {
            usage(err);
            return args.length == 0 ? EXIT_USAGE : EXIT_OK;
        }
        String command = args[0];
        if (!COMMANDS.contains(command)) {
            err.println("mcp-sentinel: 未知命令 '" + Sanitizer.forReport(command, 60)
                    + "'（可用：lock / scan / snapshot / import-config）");
            return EXIT_USAGE;
        }

        Path config = null;
        Path snapshotFile = null;
        Path baselineFile = Path.of("mcp-sentinel.lock.json");
        Path baselineDir = Path.of(".");
        boolean baselineExplicit = false;
        Path outFile = null;
        Path jsonFile = null;
        Path sarifFile = null;
        String selectedServer = null;
        boolean allTargets = false;
        boolean redactSnapshot = false;
        Finding.Severity failOn = Finding.Severity.HIGH;
        ChangeSeverity failOnChange = ChangeSeverity.BREAKING;
        boolean acceptChanges = false;
        String expectedBaseline = null;
        String expectedSurface = null;
        boolean riskOnly = false;
        java.time.Duration timeoutOverride = null;
        java.time.Duration connectTimeoutOverride = null;
        java.time.Duration requestTimeoutOverride = null;
        Integer maxToolsOverride = null;
        java.util.Set<String> seen = new java.util.LinkedHashSet<>();

        for (int i = 1; i < args.length; i++) {
            String opt = args[i];
            if (opt.startsWith("--")) {
                if (!seen.add(opt)) {
                    err.println("mcp-sentinel: 参数重复: " + Sanitizer.forReport(opt));
                    return EXIT_USAGE;
                }
            }
            switch (opt) {
                case "--config" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    config = Path.of(val);
                }
                case "--snapshot" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    snapshotFile = Path.of(val);
                }
                case "--baseline" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    baselineFile = Path.of(val);
                    baselineExplicit = true;
                }
                case "--baseline-dir" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    baselineDir = Path.of(val);
                }
                case "--server" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    selectedServer = val;
                }
                case "--all-targets" -> allTargets = true;
                case "--redact" -> redactSnapshot = true;
                case "--out" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    outFile = Path.of(val);
                }
                case "--json" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    jsonFile = Path.of(val);
                }
                case "--sarif" -> {
                    String val = requireValue(args, ++i, opt, err);
                    if (val == null) return EXIT_USAGE;
                    sarifFile = Path.of(val);
                }
                case "--accept-changes" -> acceptChanges = true;
                case "--expect-baseline", "--expect-surface" -> {
                    String value = requireValue(args, ++i, opt, err);
                    if (value == null) return EXIT_USAGE;
                    if (!value.matches("[0-9a-f]{64}")) {
                        err.println("mcp-sentinel: " + opt + " 需要完整的 64 位 SHA256 指纹");
                        return EXIT_USAGE;
                    }
                    if ("--expect-baseline".equals(opt)) expectedBaseline = value;
                    else expectedSurface = value;
                }
                case "--risk-only" -> riskOnly = true;
                case "--timeout" -> {
                    String value = requireValue(args, ++i, opt, err);
                    if (value == null) return EXIT_USAGE;
                    try {
                        long seconds = Long.parseLong(value.strip());
                        if (seconds < 1 || seconds > 86400) throw new IllegalArgumentException();
                        timeoutOverride = java.time.Duration.ofSeconds(seconds);
                    } catch (RuntimeException e) {
                        err.println("mcp-sentinel: --timeout 需要秒数，收到 '" + Sanitizer.forReport(value, 40) + "'");
                        return EXIT_USAGE;
                    }
                }
                case "--connect-timeout", "--request-timeout" -> {
                    String value = requireValue(args, ++i, opt, err);
                    if (value == null) return EXIT_USAGE;
                    java.time.Duration parsed;
                    try {
                        long seconds = Long.parseLong(value.strip());
                        if (seconds < 1 || seconds > 86400) throw new IllegalArgumentException();
                        parsed = java.time.Duration.ofSeconds(seconds);
                    } catch (RuntimeException e) {
                        err.println("mcp-sentinel: " + opt + " 需要秒数，收到 '" + Sanitizer.forReport(value, 40) + "'");
                        return EXIT_USAGE;
                    }
                    if ("--connect-timeout".equals(opt)) {
                        connectTimeoutOverride = parsed;
                    } else {
                        requestTimeoutOverride = parsed;
                    }
                }
                case "--max-tools" -> {
                    String value = requireValue(args, ++i, opt, err);
                    if (value == null) return EXIT_USAGE;
                    try {
                        int parsed = Integer.parseInt(value.strip());
                        if (parsed < 1) throw new NumberFormatException("must be >= 1");
                        maxToolsOverride = parsed;
                    } catch (RuntimeException e) {
                        err.println("mcp-sentinel: --max-tools 需要正整数，收到 '" + Sanitizer.forReport(value, 40) + "'");
                        return EXIT_USAGE;
                    }
                }
                case "--fail-on" -> {
                    String value = requireValue(args, ++i, opt, err);
                    if (value == null) return EXIT_USAGE;
                    try {
                        failOn = Finding.Severity.valueOf(value.toUpperCase(Locale.ROOT));
                    } catch (IllegalArgumentException e) {
                        err.println("mcp-sentinel: --fail-on 只能是 HIGH / MEDIUM / LOW");
                        return EXIT_USAGE;
                    }
                }
                case "--fail-on-change" -> {
                    String value = requireValue(args, ++i, opt, err);
                    if (value == null) return EXIT_USAGE;
                    try {
                        failOnChange = ChangeSeverity.parse(value);
                    } catch (IllegalArgumentException e) {
                        err.println("mcp-sentinel: " + Sanitizer.forReport(e.getMessage(), 200));
                        return EXIT_USAGE;
                    }
                }
                default -> {
                    err.println("mcp-sentinel: 未知参数 '" + Sanitizer.forReport(opt, 60) + "'");
                    return EXIT_USAGE;
                }
            }
        }

        Set<String> common = Set.of("--config", "--server", "--out");
        Set<String> online = Set.of("--timeout", "--connect-timeout", "--request-timeout", "--max-tools");
        for (String option : seen) {
            boolean allowed = common.contains(option)
                    || (!"import-config".equals(command) && online.contains(option))
                    || ("snapshot".equals(command) && "--redact".equals(option))
                    || (("scan".equals(command) || "lock".equals(command))
                        && Set.of("--baseline", "--baseline-dir", "--all-targets").contains(option))
                    || ("scan".equals(command) && Set.of("--snapshot", "--json", "--sarif", "--risk-only",
                        "--accept-changes", "--expect-baseline", "--expect-surface", "--fail-on", "--fail-on-change").contains(option));
            if (!allowed) {
                err.println("mcp-sentinel: " + option + " 不属于 " + command + " 子命令");
                return EXIT_USAGE;
            }
        }
        if (seen.contains("--baseline-dir") && !allTargets) {
            err.println("mcp-sentinel: --baseline-dir 必须配合 --all-targets");
            return EXIT_USAGE;
        }
        if (snapshotFile != null && (selectedServer != null || allTargets || seen.stream().anyMatch(online::contains))) {
            err.println("mcp-sentinel: 离线快照不能同时指定在线目标或连接选项");
            return EXIT_USAGE;
        }
        if (allTargets && "lock".equals(command) && outFile != null) {
            err.println("mcp-sentinel: 批量 lock 请使用 --baseline-dir，不能指定单个 --out");
            return EXIT_USAGE;
        }
        List<Path> outputs = new ArrayList<>();
        for (Path path : new Path[]{outFile, jsonFile, sarifFile}) if (path != null) outputs.add(path);
        if ("lock".equals(command) && outFile == null && !allTargets) outputs.add(baselineFile);
        List<Path> inputs = new ArrayList<>();
        for (Path path : new Path[]{config, snapshotFile, "scan".equals(command) ? baselineFile : null}) {
            if (path != null) inputs.add(path);
        }
        try {
            for (int a = 0; a < outputs.size(); a++) {
                for (Path input : inputs) if (samePath(outputs.get(a), input)) throw new IOException("输出路径不能覆盖配置、快照或基线");
                for (int b = a + 1; b < outputs.size(); b++) if (samePath(outputs.get(a), outputs.get(b))) throw new IOException("不同报告不能使用相同输出路径");
            }
        } catch (IOException e) {
            err.println("mcp-sentinel: " + e.getMessage());
            return EXIT_USAGE;
        }

        if ("import-config".equals(command)) {
            if (config == null) {
                err.println("mcp-sentinel: import-config 必须指定 --config");
                return EXIT_USAGE;
            }
            return doImportConfig(config, selectedServer, outFile, out, err);
        }

        if ("snapshot".equals(command)) {
            if (config == null || outFile == null) {
                err.println("mcp-sentinel: snapshot 必须同时指定 --config 与 --out");
                return EXIT_USAGE;
            }
            if (seen.contains("--sarif") || seen.contains("--json") || acceptChanges || riskOnly) {
                err.println("mcp-sentinel: snapshot 只负责采集并保存快照，不接受扫描参数");
                return EXIT_USAGE;
            }
            return doSnapshot(config, selectedServer, outFile, redactSnapshot,
                    timeoutOverride, connectTimeoutOverride, requestTimeoutOverride, maxToolsOverride, out, err);
        }

        if (config == null && snapshotFile == null) {
            err.println("mcp-sentinel: 必须指定 --config（或对 scan 指定 --snapshot）");
            return EXIT_USAGE;
        }
        if (config != null && snapshotFile != null) {
            err.println("mcp-sentinel: --config 与 --snapshot 互斥，请只指定其中一个输入源");
            return EXIT_USAGE;
        }
        if (snapshotFile != null && !"scan".equals(command)) {
            err.println("mcp-sentinel: --snapshot 只对 scan 有意义");
            return EXIT_USAGE;
        }
        if (redactSnapshot) {
            err.println("mcp-sentinel: --redact 只属于 snapshot 子命令");
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
        if (riskOnly && seen.contains("--fail-on-change")) {
            err.println("mcp-sentinel: --risk-only 与 --fail-on-change 互斥"
                    + "（前者不做漂移检测，而后者判的正是漂移）");
            return EXIT_USAGE;
        }
        if (allTargets && selectedServer != null) {
            err.println("mcp-sentinel: --all-targets 与 --server 互斥");
            return EXIT_USAGE;
        }
        if (acceptChanges && (expectedBaseline == null || expectedSurface == null)) {
            err.println("mcp-sentinel: --accept-changes 必须同时给出已审阅报告中的 --expect-baseline 与 --expect-surface");
            return EXIT_USAGE;
        }
        if (!acceptChanges && (expectedBaseline != null || expectedSurface != null)) {
            err.println("mcp-sentinel: --expect-baseline / --expect-surface 只能用于 --accept-changes");
            return EXIT_USAGE;
        }
        if (allTargets && acceptChanges) {
            err.println("mcp-sentinel: 请用 --server 逐个批准已审阅快照，不能一次批准多个目标");
            return EXIT_USAGE;
        }
        if (allTargets && baselineExplicit) {
            err.println("mcp-sentinel: --all-targets 为每个目标使用独立基线，请用 --baseline-dir 指定目录而非单个 --baseline");
            return EXIT_USAGE;
        }

        if ("lock".equals(command)) {
            if (seen.contains("--sarif") || seen.contains("--json")) {
                err.println("mcp-sentinel: lock 不产出报告或 SARIF——它只写基线，不跑扫描。");
                return EXIT_USAGE;
            }
            if (seen.contains("--fail-on") || seen.contains("--fail-on-change")) {
                err.println("mcp-sentinel: lock 不做风险判定也不做漂移比对，"
                        + "所以 --fail-on / --fail-on-change 在它上面无效"
                        + "（先 lock，阈值是 scan 时才用得上）。");
                return EXIT_USAGE;
            }
            if (seen.contains("--baseline") && seen.contains("--out")) {
                err.println("mcp-sentinel: lock 的输出位置只由一个选项决定，"
                        + "同时给 --baseline 与 --out 会让前者被忽略、实际写的是 --out。"
                        + "请只保留 --out。");
                return EXIT_USAGE;
            }
        }

        // 离线快照扫描路径（不启动任何外部服务）
        if (snapshotFile != null) {
            SurfaceSnapshot snap;
            try {
                snap = SurfaceSnapshot.read(snapshotFile);
            } catch (Exception e) {
                err.println("mcp-sentinel: 读取快照失败: " + Sanitizer.forReport(e.getMessage(), 240));
                reports.inputErrors.add(new ScanError(category(EXIT_USAGE), "SNAPSHOT_READ", e.getMessage()));
                return EXIT_USAGE;
            }
            if (snap.redacted() && !riskOnly) {
                err.println("mcp-sentinel: 该快照为脱敏副本（redacted=true），标题与描述已脱敏，"
                        + "不能作为原始指纹证据用于基线漂移比对或 --accept-changes。若仅需离线查静态规则，请加 --risk-only。");
                err.println("::error::基线不可用，脱敏快照不能用于漂移检测");
                reports.failed(ScanReport.of(snap.toSurface(), List.of(), null, "", snap.targetId(), false),
                        snapshotFile, baselineFile, EXIT_BASELINE, true, "SNAPSHOT_VALIDATION", "脱敏快照不能作为漂移或审批证据");
                return EXIT_BASELINE;
            }
            Baseline baseline = null;
            if (!riskOnly) {
                BaselineLoad loaded = loadBaseline(baselineFile, err);
                if (!loaded.ok()) {
                    err.println("::error::基线不可用，本次扫描给不出漂移结论"
                            + "（fail-closed：不会降级成「没有漂移」，也不会自动重建基线）");
                    reports.failed(ScanReport.of(snap.toSurface(), List.of(), null, "", snap.targetId(), true),
                            snapshotFile, baselineFile, EXIT_BASELINE, true, "BASELINE_READ", loaded.message());
                    return EXIT_BASELINE;
                }
                baseline = loaded.baseline();
            }
            return doScan(snap.toSurface(), snapshotFile, baselineFile, baseline, outFile, jsonFile, sarifFile,
                    failOn, failOnChange, acceptChanges, riskOnly, snap.targetId(), expectedBaseline, expectedSurface, !snap.redacted(), reports, out, err);
        }

        // 多目标批量模式（W07）
        if (allTargets) {
            return runAllTargets(command, config, baselineDir, failOn, failOnChange,
                    acceptChanges, riskOnly, timeoutOverride, connectTimeoutOverride,
                    requestTimeoutOverride, maxToolsOverride, reports, out, err);
        }

        ServerTarget target;
        try {
            target = ServerTarget.read(config, selectedServer);
        } catch (Exception e) {
            err.println("mcp-sentinel: 读取配置失败: " + Sanitizer.forReport(safeConfigError(e), 240));
            reports.inputErrors.add(new ScanError(category(EXIT_USAGE), "CONFIG_READ", safeConfigError(e)));
            return EXIT_USAGE;
        }
        target = applyOverrides(target, timeoutOverride, connectTimeoutOverride, requestTimeoutOverride, maxToolsOverride);

        {
            try {
                validateCredentials(target);
            } catch (IOException e) {
                err.println("mcp-sentinel: 配置错误: " + Sanitizer.forReport(e.getMessage(), 240));
                reports.failed(target, config, baselineFile, EXIT_USAGE, "CONFIGURATION", e.getMessage());
                return EXIT_USAGE;
            }
        }

        Baseline baseline = null;
        if ("scan".equals(command) && !riskOnly) {
            BaselineLoad loaded = loadBaseline(baselineFile, err);
            if (!loaded.ok()) {
                err.println("::error::基线不可用，本次扫描给不出漂移结论"
                        + "（fail-closed：不会降级成「没有漂移」，也不会自动重建基线）");
                reports.failed(target, config, baselineFile, EXIT_BASELINE, "BASELINE_READ", loaded.message());
                return EXIT_BASELINE;
            }
            baseline = loaded.baseline();
        }

        McpConnector.Result connection = McpConnector.connect(target);
        if (!connection.ok()) {
            err.println("mcp-sentinel: 连接服务器失败: " + Sanitizer.forReport(target.redactDiagnostic(connection.error()), 240));
            err.println("  目标: " + Sanitizer.forReport(target.describeTarget(), 200));
            reports.failed(target, config, baselineFile, EXIT_CONNECT, connection.phase(), connection.error());
            return EXIT_CONNECT;
        }
        ToolSurface surface = connection.surface();

        return switch (command) {
            case "lock" -> doLock(surface, target.identity(), outFile == null ? baselineFile : outFile, out, err);
            case "scan" -> doScan(surface, config, baselineFile, baseline, outFile, jsonFile, sarifFile,
                    failOn, failOnChange, acceptChanges, riskOnly, target.identity(), expectedBaseline, expectedSurface, true, reports, out, err);
            default -> throw new IllegalStateException(
                    "命令 '" + command + "' 通过了入口校验却没有对应的处理分支");
        };
    }

    private static ServerTarget applyOverrides(ServerTarget target,
                                               java.time.Duration timeout,
                                               java.time.Duration connectTimeout,
                                               java.time.Duration requestTimeout,
                                               Integer maxTools) {
        if (timeout != null) {
            target = target.withTimeout(timeout);
        }
        if (connectTimeout != null) {
            target = target.withConnectTimeout(connectTimeout);
        }
        if (requestTimeout != null) {
            target = target.withRequestTimeout(requestTimeout);
        }
        if (maxTools != null) {
            target = target.withMaxTools(maxTools);
        }
        return target;
    }

    private static int doImportConfig(Path configFile, String selectedServer, Path outFile,
                                      PrintStream out, PrintStream err) {
        ServerTarget target;
        try {
            target = ServerTarget.read(configFile, selectedServer);
        } catch (Exception e) {
            err.println("mcp-sentinel: 读取配置失败: " + Sanitizer.forReport(safeConfigError(e), 240));
            return EXIT_USAGE;
        }
        String normalized = target.toNormalizedJson();
        out.println(normalized);
        if (outFile != null) {
            try {
                if (outFile.getParent() != null) {
                    Files.createDirectories(outFile.getParent());
                }
                Files.writeString(outFile, normalized, StandardCharsets.UTF_8);
                err.println("已导出标准化配置: " + display(outFile));
            } catch (IOException e) {
                err.println("mcp-sentinel: 写出配置失败: " + Sanitizer.forReport(e.getMessage(), 240));
                return EXIT_OUTPUT;
            }
        }
        return EXIT_OK;
    }

    private static int doSnapshot(Path configFile, String selectedServer, Path outFile, boolean redact,
                                  java.time.Duration timeout, java.time.Duration connectTimeout,
                                  java.time.Duration requestTimeout, Integer maxTools,
                                  PrintStream out, PrintStream err) {
        ServerTarget target;
        try {
            target = ServerTarget.read(configFile, selectedServer);
        } catch (Exception e) {
            err.println("mcp-sentinel: 读取配置失败: " + Sanitizer.forReport(safeConfigError(e), 240));
            return EXIT_USAGE;
        }
        target = applyOverrides(target, timeout, connectTimeout, requestTimeout, maxTools);
        {
            try {
                validateCredentials(target);
            } catch (IOException e) {
                err.println("mcp-sentinel: 配置错误: " + Sanitizer.forReport(e.getMessage(), 240));
                return EXIT_USAGE;
            }
        }
        McpConnector.Result connection = McpConnector.connect(target);
        if (!connection.ok()) {
            err.println("mcp-sentinel: 连接服务器失败: " + Sanitizer.forReport(connection.error(), 240));
            err.println("  目标: " + Sanitizer.forReport(target.describeTarget(), 200));
            return EXIT_CONNECT;
        }
        SurfaceSnapshot snapshot = SurfaceSnapshot.of(connection.surface(), redact, target.identity());
        try {
            snapshot.write(outFile);
        } catch (IOException e) {
            err.println("mcp-sentinel: 写入快照失败: " + Sanitizer.forReport(e.getMessage(), 240));
            return EXIT_OUTPUT;
        }
        out.println("已保存工具面快照: " + display(outFile));
        out.println("  服务器      : " + Sanitizer.forReport(snapshot.serverName(), 120));
        out.println("  工具数      : " + snapshot.tools().size());
        out.println("  脱敏模式    : " + (redact ? "是（不可作基线指纹证据）" : "否（含完整定义）"));
        return EXIT_OK;
    }

    private static int runAllTargets(String command, Path configFile, Path baselineDir,
                                     Finding.Severity failOn, ChangeSeverity failOnChange,
                                     boolean acceptChanges, boolean riskOnly,
                                     java.time.Duration timeout, java.time.Duration connectTimeout,
                                     java.time.Duration requestTimeout, Integer maxTools,
                                     Reports reports, PrintStream out, PrintStream err) {
        List<ServerTarget> targets;
        try {
            targets = ServerTarget.readAll(configFile);
        } catch (Exception e) {
            err.println("mcp-sentinel: 读取配置失败: " + Sanitizer.forReport(safeConfigError(e), 240));
            reports.inputErrors.add(new ScanError(category(EXIT_USAGE), "CONFIG_READ", safeConfigError(e)));
            return EXIT_USAGE;
        }
        int worstCode = EXIT_OK;
        for (ServerTarget raw : targets) {
            ServerTarget target = applyOverrides(raw, timeout, connectTimeout, requestTimeout, maxTools);
            String encodedName = Sanitizer.forUriSegment(target.serverName());
            String safeName = encodedName.substring(0, Math.min(60, encodedName.length()))
                    + "-" + ToolFingerprint.sha256(target.identity()).substring(0, 16);
            Path targetBaseline = baselineDir.resolve(safeName + ".lock.json");

            {
                try {
                    validateCredentials(target);
                } catch (IOException e) {
                    err.println("mcp-sentinel: [" + Sanitizer.forReport(target.serverName(), 80)
                            + "] 配置错误: " + Sanitizer.forReport(e.getMessage(), 200));
                    worstCode = pickWorseExitCode(worstCode, EXIT_USAGE);
                    reports.failed(target, configFile, targetBaseline, EXIT_USAGE, "CONFIGURATION", e.getMessage());
                    continue;
                }
            }

            Baseline baseline = null;
            if ("scan".equals(command) && !riskOnly) {
                BaselineLoad loaded = loadBaseline(targetBaseline, err);
                if (!loaded.ok()) {
                    err.println("::error::基线不可用，目标 '" + Sanitizer.forReport(target.serverName(), 80)
                            + "' 本次扫描给不出漂移结论");
                    worstCode = pickWorseExitCode(worstCode, EXIT_BASELINE);
                    reports.failed(target, configFile, targetBaseline, EXIT_BASELINE, "BASELINE_READ", loaded.message());
                    continue;
                }
                baseline = loaded.baseline();
            }

            McpConnector.Result connection = McpConnector.connect(target);
            if (!connection.ok()) {
                err.println("mcp-sentinel: [" + Sanitizer.forReport(target.serverName(), 80)
                        + "] 连接服务器失败: " + Sanitizer.forReport(target.redactDiagnostic(connection.error()), 200));
                worstCode = pickWorseExitCode(worstCode, EXIT_CONNECT);
                reports.failed(target, configFile, targetBaseline, EXIT_CONNECT, connection.phase(), connection.error());
                continue;
            }
            int reportCount = reports.items.size();
            int code = "lock".equals(command)
                    ? doLock(connection.surface(), target.identity(), targetBaseline, out, err)
                    : doScan(connection.surface(), configFile, targetBaseline, baseline,
                            null, null, null, failOn, failOnChange, acceptChanges, riskOnly,
                            target.identity(), null, null, true, reports, out, err);
            if ("scan".equals(command) && reports.items.size() == reportCount)
                reports.failed(target, configFile, targetBaseline, code, "SCAN", "目标检查未完成");
            worstCode = pickWorseExitCode(worstCode, code);
        }
        return worstCode;
    }

    private static int pickWorseExitCode(int current, int candidate) {
        if (candidate == EXIT_OK) return current;
        if (current == EXIT_OK) return candidate;
        List<Integer> priority = List.of(EXIT_BASELINE, EXIT_DRIFT, EXIT_FINDINGS, EXIT_CONNECT, EXIT_USAGE, EXIT_OUTPUT);
        int curRank = priority.indexOf(current);
        int candRank = priority.indexOf(candidate);
        return (candRank >= 0 && (curRank < 0 || candRank < curRank)) ? candidate : current;
    }

    private static int doLock(ToolSurface surface, String targetId, Path file, PrintStream out, PrintStream err) {
        try {
            Baseline.of(surface, targetId, List.of()).writeExpected(file, null);
        } catch (Exception e) {
            err.println("mcp-sentinel: 写入基线失败: " + Sanitizer.forReport(e.getMessage(), 240));
            return EXIT_USAGE;
        }
        out.println("已锁定工具面基线: " + display(file));
        out.println("  服务器      : " + Sanitizer.forReport(surface.serverName(), 120));
        out.println("  工具数      : " + surface.tools().size());
        out.println("  工具面指纹  : " + surface.shortFingerprint());
        out.println();
        out.println("请把该文件提交进版本库——工具定义的变化应当像代码变化一样出现在评审里。");
        return EXIT_OK;
    }

    private static int doScan(ToolSurface surface, Path configFile, Path baselineFile,
                              Baseline loadedBaseline, Path outFile, Path jsonFile, Path sarifFile,
                              Finding.Severity failOn, ChangeSeverity failOnChange,
                              boolean acceptChanges, boolean riskOnly,
                              String targetId, String expectedBaseline, String expectedSurface,
                              boolean fingerprintsAvailable,
                              Reports reports, PrintStream out, PrintStream err) {
        if (!riskOnly && !loadedBaseline.targetId().equals(targetId)) {
            err.println("mcp-sentinel: 基线属于其他配置目标，请选择正确基线；文件未改动");
            reports.failed(ScanReport.of(surface, List.of(), null, loadedBaseline.surfaceFingerprint(), targetId, fingerprintsAvailable),
                    configFile, baselineFile, EXIT_BASELINE, true, "BASELINE_TARGET", "基线目标标识与当前目标不一致");
            return EXIT_BASELINE;
        }
        if (acceptChanges && (!loadedBaseline.surfaceFingerprint().equals(expectedBaseline)
                || !surface.fingerprint().equals(expectedSurface))) {
            err.println("mcp-sentinel: 当前基线或工具面与已审阅指纹不一致；未批准，请重新扫描");
            reports.failed(ScanReport.of(surface, List.of(), null, loadedBaseline.surfaceFingerprint(), targetId, fingerprintsAvailable),
                    configFile, baselineFile, EXIT_BASELINE, true, "APPROVAL", "基线或工具面指纹与已审阅值不一致，未写回基线");
            return EXIT_BASELINE;
        }
        List<Finding> findings = RiskRules.evaluate(surface);
        Baseline baseline = loadedBaseline;
        SurfaceDiff diff = null;

        if (riskOnly) {
            out.println("模式：--risk-only（显式跳过基线比对，本次不检测工具面漂移）");
        } else {
            diff = baseline.diffAgainst(surface);
        }

        if (acceptChanges) {
            if (baseline == null) {
                err.println("mcp-sentinel: --accept-changes 需要先有一份可读的基线文件");
                return EXIT_USAGE;
            }
            List<Change> accepted = diff == null ? List.of() : diff.changes();
            Baseline before = baseline;
            Baseline updated = Baseline.of(surface, targetId, mergeAccepted(baseline, diff, surface.fingerprint()));
            boolean contentChanged = !updated.sameContentAs(before);
            boolean written = !accepted.isEmpty() && contentChanged;
            if (written) {
                try {
                    updated.writeExpected(baselineFile, baseline);
                    out.println("已接受 " + accepted.size() + " 处变更并写回基线: "
                            + display(baselineFile));
                } catch (IOException e) {
                    err.println("mcp-sentinel: 写回基线失败: " + Sanitizer.forReport(e.getMessage(), 240));
                    reports.failed(ScanReport.of(surface, findings, diff, baseline.surfaceFingerprint(), targetId, fingerprintsAvailable),
                            configFile, baselineFile, EXIT_BASELINE, true, "BASELINE_WRITE", e.getMessage());
                    return EXIT_BASELINE;
                }
            } else if (contentChanged) {
                err.println("mcp-sentinel: 工具面指纹变了，却没有任何一条变更可以被批准——"
                        + "基线未改动；请重新运行 lock 建立新基线，或报告这个输入。");
                return EXIT_USAGE;
            } else {
                out.println("没有需要批准的变更——工具面与基线一致，基线文件未改动。");
            }
            printAcceptanceSummary(accepted, before, updated, findings, failOn, written, out);
            diff = new SurfaceDiff(accepted, accepted.stream().map(Change::digest).collect(java.util.stream.Collectors.toSet()), diff.paths());
        }

        ScanReport report = ScanReport.of(surface, findings, diff,
                baseline == null ? "" : baseline.surfaceFingerprint(), targetId, fingerprintsAvailable);
        String rendered = report.render();
        out.println(rendered);

        List<Change> blocking = diff == null ? List.of() : diff.blocking(failOnChange);
        boolean hasFindings = report.hasAtLeast(failOn);
        int preliminaryExit = !blocking.isEmpty() ? EXIT_DRIFT : (hasFindings ? EXIT_FINDINGS : EXIT_OK);
        String errorCategory = switch (preliminaryExit) {
            case EXIT_DRIFT -> "UNAPPROVED_DRIFT";
            case EXIT_FINDINGS -> "STATIC_RISK_FINDINGS";
            default -> "NONE";
        };
        if (preliminaryExit != EXIT_OK) report = report.withErrors(List.of(new ScanError(errorCategory,
                "POLICY_CHECK", !blocking.isEmpty() ? "存在 " + blocking.size() + " 处达到阈值的未批准变化" : "静态风险达到 " + failOn + " 阈值")));

        reports.items.add(new ReportItem(report, configFile, riskOnly ? null : baselineFile, preliminaryExit, true));

        if (hasFindings) {
            err.println("::error::存在风险项，最高 " + report.highestSeverity()
                    + " 级别（阻断阈值 " + failOn + "）");
        }
        if (!blocking.isEmpty()) {
            ChangeSeverity worst = blocking.stream()
                    .map(Change::severity)
                    .max(Comparator.comparingInt(Enum::ordinal))
                    .orElse(failOnChange);
            err.println("::error::MCP 工具面有 " + blocking.size() + " 处未批准的变更，最高 "
                    + worst + " 级别（共 " + diff.totalChanges() + " 处变化，阻断阈值 " + failOnChange + "）");
        }
        if (!blocking.isEmpty()) {
            return EXIT_DRIFT;
        }
        if (hasFindings) {
            return EXIT_FINDINGS;
        }
        return EXIT_OK;
    }

    private record BaselineLoad(Baseline baseline, String message) {
        boolean ok() {
            return baseline != null;
        }
    }

    private static BaselineLoad loadBaseline(Path baselineFile, PrintStream err) {
        if (!Files.exists(baselineFile)) {
            err.println("mcp-sentinel: 找不到基线文件 " + display(baselineFile)
                    + "，无法检测工具面漂移。");
            err.println("  首次使用：运行 `mcp-sentinel lock --config <配置> --out " + display(baselineFile)
                    + "`，并把生成的基线提交进版本库。");
            err.println("  若你确实只想跑静态风险规则、不做漂移检测：显式加 `--risk-only`。");
            return new BaselineLoad(null, "基线文件不存在，必须先建立并审阅可信基线");
        }
        if (!Files.isRegularFile(baselineFile)) {
            err.println("mcp-sentinel: 基线路径不是普通文件：" + display(baselineFile)
                    + "（可能是目录、符号链接指向的目标不存在，或权限不足）。");
            return new BaselineLoad(null, "基线路径不是普通文件或无法访问");
        }
        try {
            return new BaselineLoad(Baseline.read(baselineFile), "");
        } catch (Exception e) {
            err.println("mcp-sentinel: 基线不可用，漂移检测无法进行：" + Sanitizer.forReport(e.getMessage(), 300));
            err.println("  不会自动重建基线——请人工确认这份文件为何不可读，"
                    + "再决定是否重新运行 `mcp-sentinel lock`。");
            return new BaselineLoad(null, e.getMessage());
        }
    }

    private static void printAcceptanceSummary(List<Change> accepted, Baseline before, Baseline after,
                                               List<Finding> findings,
                                               Finding.Severity failOn, boolean written,
                                               PrintStream out) {
        Map<String, String> previousFingerprints = new LinkedHashMap<>();
        for (Baseline.ToolEntry entry : before.tools()) {
            previousFingerprints.putIfAbsent(entry.tool().name(), entry.fingerprint());
        }

        out.println();
        out.println("本次批准的变更（审计记录绑定目标及前后快照，不批准其他上下文的变化）：");
        if (accepted.isEmpty()) {
            out.println("  （无——工具面与基线一致，没有任何变更需要批准）");
        }
        Map<String, Integer> bySeverity = new TreeMap<>();
        for (Change change : accepted) {
            bySeverity.merge(change.severity().name(), 1, Integer::sum);
            String was = previousFingerprints.getOrDefault(change.toolName(), "-");
            out.println("  [%s] %-28s %-22s %s → %s".formatted(
                    change.severity(), change.id(), Sanitizer.forReport(change.describe(), 80),
                    shortDigest(was), shortDigest(change.afterDigest())));
            if (!change.detail().isBlank()) {
                out.println("      " + Sanitizer.forReport(change.detail(), 250));
            }
            out.println("      变更指纹 " + change.digest());
        }
        out.println("  按级别统计: " + bySeverity);

        out.println();
        out.println("工具面指纹   : " + shortFingerprint(before) + " → " + shortFingerprint(after));
        if (written) {
            out.println("基线写回时间 : " + after.generatedAt());
        } else {
            out.println("基线改动     : 无（工具面与基线一致，未写文件）");
        }

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

    private static List<Baseline.AcceptedChange> mergeAccepted(Baseline baseline, SurfaceDiff diff, String afterFingerprint) {
        Map<String, Baseline.AcceptedChange> merged = new LinkedHashMap<>();
        for (Baseline.AcceptedChange change : baseline.acceptedChanges()) {
            merged.put(change.digest(), change);
        }
        if (diff != null) {
            for (Change change : diff.changes()) {
                merged.putIfAbsent(change.digest(),
                        new Baseline.AcceptedChange(change.id(), change.toolName(), change.digest(),
                                baseline.targetId(), baseline.surfaceFingerprint(), afterFingerprint));
            }
        }
        return new ArrayList<>(merged.values());
    }

    private static String requireValue(String[] args, int index, String option, PrintStream err) {
        if (index >= args.length || args[index].startsWith("--")) {
            err.println("mcp-sentinel: 选项 " + option + " 参数缺值");
            return null;
        }
        return args[index];
    }

    private static boolean samePath(Path a, Path b) throws IOException {
        return a.toAbsolutePath().normalize().equals(b.toAbsolutePath().normalize())
                || (Files.exists(a) && Files.exists(b) && Files.isSameFile(a, b));
    }

    private static String display(Path path) {
        return Sanitizer.forReport(path.toAbsolutePath().toString(), 300);
    }

    private static void validateCredentials(ServerTarget target) throws IOException {
        if (target.transport() == ServerTarget.Transport.STREAMABLE_HTTP) target.resolveHeaders(System::getenv);
        else target.resolveEnvironment(System::getenv);
    }

    private static String safeConfigError(Exception error) {
        if (error instanceof java.nio.file.NoSuchFileException) return "配置文件不存在";
        if (error instanceof com.fasterxml.jackson.core.JsonProcessingException) return "配置 JSON 格式无效";
        // A parser diagnostic may contain an input fragment; configuration values
        // have not yet been loaded, so do not echo that fragment into a report.
        return "配置无法读取或字段不符合支持的格式；请检查 transport（stdio / streamable-http）、url、command 等字段（"
                + error.getClass().getSimpleName() + "）";
    }

    private static String optionValue(String[] args, String key) {
        String value = null;
        for (int i = 1; i + 1 < args.length; i++) if (key.equals(args[i]) && !args[i + 1].startsWith("--")) value = args[i + 1];
        return value;
    }

    private static String category(int code) {
        return switch (code) {
            case EXIT_OK -> "NONE";
            case EXIT_USAGE -> "USAGE_OR_CONFIG_ERROR";
            case EXIT_CONNECT -> "CONNECTION_FAILED";
            case EXIT_FINDINGS -> "STATIC_RISK_FINDINGS";
            case EXIT_DRIFT -> "UNAPPROVED_DRIFT";
            case EXIT_BASELINE -> "BASELINE_UNAVAILABLE";
            default -> "OUTPUT_WRITE_FAILED";
        };
    }

    /** Export once, after the final status is known; failures also get a report. */
    private static int writeReports(String[] args, Reports reports, int code, PrintStream out, PrintStream err) {
        String jsonPath = optionValue(args, "--json");
        String sarifPath = optionValue(args, "--sarif");
        String textPath = optionValue(args, "--out");
        if (jsonPath == null && sarifPath == null && textPath == null) return code;
        // Do not turn a rejected aliasing invocation into an overwrite in the
        // failure-report path. The same protection applies to hard links.
        try {
            List<Path> destinations = new ArrayList<>();
            for (String value : new String[]{jsonPath, sarifPath, textPath}) {
                if (value == null) continue;
                Path path = Path.of(value);
                for (String key : List.of("--config", "--snapshot", "--baseline")) {
                    String input = optionValue(args, key);
                    if (input != null && samePath(path, Path.of(input))) return EXIT_USAGE;
                }
                if (samePath(path, Path.of("mcp-sentinel.lock.json"))) return EXIT_USAGE;
                for (ReportItem item : reports.items) {
                    if ((item.source != null && samePath(path, item.source))
                            || (item.baseline != null && samePath(path, item.baseline))) return EXIT_USAGE;
                }
                for (Path existing : destinations) if (samePath(path, existing)) return EXIT_USAGE;
                destinations.add(path);
            }
        } catch (Exception e) {
            err.println("mcp-sentinel: 报告路径无效: " + Sanitizer.forReport(e.getMessage()));
            return pickWorseExitCode(code, EXIT_OUTPUT);
        }
        if (reports.items.isEmpty()) reports.items.add(new ReportItem(
                new ScanReport("unavailable", "", 0, List.of(), null).withErrors(reports.inputErrors.isEmpty()
                        ? List.of(new ScanError(category(code), "ARGUMENTS", "命令参数校验失败，请检查必需选项、互斥选项及输入路径"))
                        : reports.inputErrors), null, null, code, false));
        List<String> outputErrors = new ArrayList<>();
        if (textPath != null) {
            try {
                StringBuilder text = new StringBuilder();
                for (ReportItem item : reports.items) text.append(item.complete ? item.report.render()
                        : "扫描未完成，错误类别: " + category(item.code) + "\n");
                AtomicFiles.write(Path.of(textPath), text.toString(), p -> { });
                err.println("报告已写出: " + Sanitizer.forReport(Path.of(textPath).toAbsolutePath().toString(), 240));
            } catch (Exception e) {
                err.println("mcp-sentinel: 写出报告失败: " + Sanitizer.forReport(e.getMessage(), 240));
                outputErrors.add("TEXT");
            }
        }
        if (sarifPath != null) {
            try {
                ObjectNode root = JSON.createObjectNode();
                root.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
                root.put("version", "2.1.0");
                var runs = root.putArray("runs");
                for (ReportItem item : reports.items) {
                    SarifWriter.Source source = item.source == null ? SarifWriter.Source.of("mcp-sentinel.lock.json")
                            : SarifWriter.Source.fromFiles(item.source, item.complete ? item.baseline : null);
                    ObjectNode run = (ObjectNode) JSON.readTree(SarifWriter.render(item.report, source)).path("runs").get(0);
                    run.putObject("automationDetails").put("id", item.report.targetId());
                    var invocation = run.putArray("invocations").addObject();
                    invocation.put("executionSuccessful", item.complete && item.code != EXIT_BASELINE && item.code != EXIT_USAGE && item.code != EXIT_CONNECT);
                    invocation.put("exitCode", item.code);
                    runs.add(run);
                }
                AtomicFiles.write(Path.of(sarifPath), JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root), p -> { });
                out.println("SARIF 已写出: " + Sanitizer.forReport(Path.of(sarifPath).toAbsolutePath().toString(), 240));
            } catch (Exception e) {
                err.println("mcp-sentinel: 写出 SARIF 失败: " + Sanitizer.forReport(e.getMessage(), 240));
                outputErrors.add("SARIF");
            }
        }
        int finalCode = outputErrors.isEmpty() ? code : pickWorseExitCode(code, EXIT_OUTPUT);
        if (jsonPath != null) {
            try {
                Finding.Severity risk = Finding.Severity.HIGH;
                ChangeSeverity drift = ChangeSeverity.BREAKING;
                try {
                    if (optionValue(args, "--fail-on") != null) risk = Finding.Severity.valueOf(optionValue(args, "--fail-on").toUpperCase(Locale.ROOT));
                    if (optionValue(args, "--fail-on-change") != null) drift = ChangeSeverity.parse(optionValue(args, "--fail-on-change"));
                } catch (IllegalArgumentException ignored) { }
                var targets = JSON.createArrayNode();
                for (ReportItem item : reports.items) {
                    ObjectNode node = (ObjectNode) JSON.readTree(item.report.renderJson(risk, drift, item.code, category(item.code)));
                    node.put("collectionStatus", item.complete ? "COMPLETE" : "FAILED");
                    targets.add(node);
                }
                boolean multiTarget = java.util.Arrays.asList(args).contains("--all-targets");
                ObjectNode root = multiTarget ? JSON.createObjectNode() : (ObjectNode) targets.get(0);
                if (multiTarget) {
                    root.put("reportVersion", ScanReport.REPORT_VERSION);
                    root.put("toolVersion", Version.value());
                    root.put("mode", "MULTI_TARGET");
                    root.set("targets", targets);
                    root.put("collectionStatus", reports.items.stream().allMatch(i -> i.complete) ? "COMPLETE"
                            : reports.items.stream().anyMatch(i -> i.complete) ? "PARTIAL" : "FAILED");
                    var aggregateErrors = root.putArray("errors");
                    for (ReportItem item : reports.items) for (ScanError error : item.report.errors())
                        aggregateErrors.addObject().put("targetId", item.report.targetId()).put("category", error.category())
                                .put("phase", error.phase()).put("message", error.message());
                }
                root.put("exitCode", finalCode);
                root.put("status", finalCode == EXIT_OK ? "PASS" : "FAIL");
                root.put("errorCategory", category(finalCode));
                var errors = root.putArray("outputErrors");
                outputErrors.forEach(errors::add);
                var failures = (com.fasterxml.jackson.databind.node.ArrayNode) root.withArray("errors");
                for (String kind : outputErrors) failures.addObject().put("category", category(EXIT_OUTPUT))
                        .put("phase", "REPORT_WRITE").put("message", kind + " 报告无法写入目标路径");
                root.put("generatedAt", java.time.Instant.now().toString());
                AtomicFiles.write(Path.of(jsonPath), JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root), p -> { });
                err.println("JSON 报告已写出: " + Sanitizer.forReport(Path.of(jsonPath).toAbsolutePath().toString(), 240));
            } catch (Exception e) {
                outputErrors.add("JSON");
                finalCode = pickWorseExitCode(finalCode, EXIT_OUTPUT);
            }
        }
        if (!outputErrors.isEmpty()) err.println("::error::输出产物写入失败: " + outputErrors);
        return finalCode;
    }

    private static void usage(PrintStream err) {
        err.println("""
                mcp-sentinel - MCP 工具面安全扫描器

                用法:
                  mcp-sentinel lock --config <配置> [--server <名称>] [--out <基线文件>]
                  mcp-sentinel scan (--config <配置> | --snapshot <快照文件>) [选项]
                  mcp-sentinel snapshot --config <配置> [--server <名称>] --out <快照文件> [--redact]
                  mcp-sentinel import-config --config <客户端配置> [--server <名称>] [--out <文件>]
                  mcp-sentinel --version                     打印本产物自带的版本号

                选项:
                  --baseline <文件>        基线的位置（默认 mcp-sentinel.lock.json）
                  --server <名称>          从含 mcpServers 的多目标配置中选择指定目标
                  --all-targets            扫描或锁定 mcpServers 中的全部启用目标
                  --baseline-dir <目录>    配合 --all-targets 指定各目标基线所在目录（默认当前目录）
                  --risk-only              只跑静态风险规则，不做漂移检测（显式选择）
                  --out <文件>             把文本报告、基线或导入配置另存一份
                  --json <文件>            输出版本化机器可读 JSON 扫描报告
                  --sarif <文件>           输出 SARIF 2.1.0
                  --redact                 配合 snapshot 导出脱敏快照（抹去标题与描述）
                  --fail-on LEVEL          风险规则在哪个级别阻断（HIGH / MEDIUM / LOW，默认 HIGH）
                  --fail-on-change LEVEL   工具面变更在哪个级别阻断
                                           （INFO / BREAKING / DANGEROUS，默认 BREAKING）
                  --accept-changes         批准本次变更并写回基线（有意的迭代走这一步）
                  --expect-baseline SHA    已审阅旧基线的完整指纹（批准时必需）
                  --expect-surface SHA     已审阅新工具面的完整指纹（批准时必需）
                  --timeout N              兼容旧用法：同时设置连接与请求超时秒数
                  --connect-timeout N      HTTP 建连超时秒数（默认 20）
                  --request-timeout N      MCP 初始化与工具列表请求超时秒数（默认 20）
                  --max-tools N            单目标允许的最大工具数上限（默认 1000）

                退出码: 0 通过 · 1 用法或配置错误 · 2 连接失败 · 3 命中风险 · 4 工具面有未批准变更
                        · 5 基线不可用（漂移检测未生效）· 6 输出产物写入失败
                """);
    }
}
