# 离线候选体验

这是尚未稳定发行的候选包，真实依赖告警仍待核实，人工验收由维护者暂缓。只在专用目录体验合成数据；包不会联网启动 MCP 服务。

需要 Java 21。解压 ZIP 后先核对外部提供的 ZIP SHA256，再核对包内 SHA256SUMS.txt。Windows 可使用 Get-FileHash，Linux 可使用 sha256sum；摘要用于检查内容一致，可信来源仍由交付渠道确认。candidate-manifest.json 标识源码和已测试 JAR，包外 candidate.json 记录最终双平台消费结果。

在解压目录打开终端，依次执行下面五步。Windows 建议使用 PowerShell 7；已有系统 PowerShell 也可直接执行下方 Java 命令。操作中生成的内容只写入 work/，重新执行 init 会重置演示基线。

| 步骤 | Linux | Windows PowerShell 7 | 正常退出码 |
| --- | --- | --- | --- |
| 初始化并扫描 | sh ./demo.sh init | ./demo.ps1 init | 0 |
| 查看合成变化 | sh ./demo.sh review | ./demo.ps1 review | 4 |
| 审阅后批准 | sh ./demo.sh approve BEFORE AFTER | ./demo.ps1 approve BEFORE AFTER | 0 |
| 再次扫描 | sh ./demo.sh rescan | ./demo.ps1 rescan | 0 |
| 验证缺失基线 | sh ./demo.sh missing | ./demo.ps1 missing | 5 |

第二步出现退出 4 是预期的漂移阻断。阅读 work/02-drift.json 中的变化，再将 baselineFingerprint 和 surfaceFingerprint 两个完整值分别替换 BEFORE、AFTER；批准命令不会替你推断或接受未审阅的指纹。错误或过期指纹必须退出 5。

每个入口调用的都是 java -jar mcp-sentinel.jar。也可直接执行：

```text
java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --json work/review.json
java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --accept-changes --expect-baseline BEFORE --expect-surface AFTER
```

本包的例子只演示工具声明变化。静态风险提示与漂移是两项检查，批准漂移不会消除风险。检查没有执行时，JSON v3 的 checks 显示 NOT_RUN，不能据此认定安全。第五步应退出 5 且两项检查为 NOT_RUN。

报告格式为 v3，基线 3、快照 1、规范化 2。保留 candidate-manifest.json、包外回执、运行系统/Java 版本、失败步骤与 work/ 报告以便复现。团队真实配置、令牌和快照应先脱敏，不默认上传。实际外部体验、人工标签和试点人数由参与者的证据登记，本包自动复跑不增加这些计数。
