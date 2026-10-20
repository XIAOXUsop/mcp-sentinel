# XIAOXUsop mcp-sentinel

MCP 工具声明面的 lockfile 与 CI 审查器。锁定工具定义，解释变化，阻断未批准的漂移，并运行不依赖模型服务的本地风险规则。

Java 21 · MIT · stdio 与 Streamable HTTP。当前工作树是 **v0.6.0 候选实现**，正式发行以 [Releases](https://github.com/XIAOXUsop/mcp-sentinel/releases) 为准。[English](docs/README.en.md)

2026-10-19 的全面检视另发现在线采集、分级和发布门禁等问题；当前修复与验收见 [执行记录](docs/execution-status.md)，原始证据保留在 [检视归档](docs/reviews/2026-10-19/README.md)。

## 五分钟离线演示

先从源码构建，再生成固定的演示基线和两个快照：

```sh
./mvnw -B verify
java --class-path target/mcp-sentinel.jar scripts/CreateDemo.java
java -jar target/mcp-sentinel.jar scan --snapshot target/demo/before.snapshot.json --baseline target/demo/baseline.json
java -jar target/mcp-sentinel.jar scan --snapshot target/demo/after.snapshot.json --baseline target/demo/baseline.json --json target/demo/review.json --sarif target/demo/review.sarif
```

Windows 将 `./mvnw` 换为 `./mvnw.cmd`。第一次扫描应退出 0；第二次删除了 oneOf 的重复分支，应报告漂移并退出 4。演示无需启动 MCP 服务、网络或密钥。生成文件均在 `target/demo`。

阅读报告与快照后，使用报告中两个完整指纹批准整个快照：

```sh
java -jar target/mcp-sentinel.jar scan --snapshot target/demo/after.snapshot.json --baseline target/demo/baseline.json --accept-changes --expect-baseline <baselineFingerprint> --expect-surface <surfaceFingerprint>
```

批准后再次扫描同一快照应通过。两个预期指纹任意一个不符时拒绝批准。静态风险告警不会因批准而消失。

最后使用固定的无效基线，验证失败不会显示为通过；该命令应退出 5：

```sh
java -jar target/mcp-sentinel.jar scan --snapshot target/demo/after.snapshot.json --baseline target/demo/invalid-baseline.json --json target/demo/failed.json
```

## 接入真实服务

stdio 配置：

```json
{"server":"internal-files-reader","command":"java","args":["-jar","/absolute/path/server.jar"],"env":{"API_TOKEN":"${MCP_TOKEN}"}}
```

Streamable HTTP 配置：

```json
{"server":"internal-platform-reader","transport":"streamable-http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${MCP_TOKEN}"},"connectTimeoutSeconds":20,"requestTimeoutSeconds":20,"maxTools":1000}
```

在线采集会启动配置中的 stdio 进程或访问 HTTP 服务。普通工具调用 `tools/call` 不在扫描流程中。只对已经审阅的配置执行在线命令；配置导入本身不启动服务。

```sh
# 首次信任建立：人工审阅服务后锁定，审阅生成文件，再提交版本库
java -jar target/mcp-sentinel.jar lock --config mcp.json --out mcp-sentinel.lock.json

# 普通检查：读取既有可信基线，不重新 lock，不自动批准
java -jar target/mcp-sentinel.jar scan --config mcp.json --baseline mcp-sentinel.lock.json --json report.json --sarif report.sarif

# 保存快照，后续离线复跑
java -jar target/mcp-sentinel.jar snapshot --config mcp.json --out surface.snapshot.json
java -jar target/mcp-sentinel.jar scan --snapshot surface.snapshot.json --baseline mcp-sentinel.lock.json
```

在线与离线采集的目标标识必须一致。目标标识使用配置别名、传输及命令或 HTTP origin；不保存请求头、环境变量值、URL 查询和命令参数的摘要。同一服务器的不同角色或环境必须使用不同别名和独立基线。身份绑定不能证明服务进程或域名所有者可信。

## 客户端配置与多个目标

支持单目标格式和明确的 `mcpServers` 对象。多个目标时必须选择；`mcpServers` 的键作为稳定别名。支持 command、args、env、transport 或 type、url、headers、disabled 和超时／数量配置。未知字段（包括尚未支持的 cwd）明确拒绝，不静默丢弃。单目标缺省 stdio；`mcpServers` 中只有 url 时推断为 HTTP。旧 SSE 不支持。

```sh
java -jar target/mcp-sentinel.jar import-config --config client.json --server files --out files.mcp.json
java -jar target/mcp-sentinel.jar lock --config client.json --all-targets --baseline-dir baselines
java -jar target/mcp-sentinel.jar scan --config client.json --all-targets --baseline-dir baselines --json batch.json --sarif batch.sarif
```

批量基线名为编码后的别名前缀、身份摘要和 `.lock.json`，避免 Windows 大小写碰撞。每个目标独立报告；有目标失败则整体失败。SARIF 每个目标独立 run 和 automationDetails.id。批量批准不支持，请用 `--server` 逐个审阅和批准。

`snapshot --redact` 只移除工具顶层标题与描述，**不能保证删除 Schema、注解或名称中的敏感信息**。脱敏副本只能用于显式 `--risk-only` 检查，不能用于漂移或批准。分享前仍需检查其内容。

## 比较与基线迁移

指纹覆盖 name、title、description、inputSchema、outputSchema、annotations。Schema 与实例值分开处理，enum 候选值中的数组保持顺序，oneOf 保留重复次数；含引用的文档保守保留数组结构。描述首尾空白与换行格式按已声明政策归一。未知扩展不猜测语义。

共 **29 类变更**，分为 INFO、BREAKING、DANGEROUS；默认在 BREAKING 及以上阻断。类型与约束放宽、描述变化、未解释路径按危险变化处理。规则声明解释范围后，再独立核对每个结构路径，剩余路径始终追加阻断项。已支持关键字的非法形态在指纹计算前拒绝，含引用的文档也执行校验。等价写法可报告 INFO，不等于完整的 JSON Schema 等价证明或所有方言合法性认证。

v0.6 使用基线格式 **3**、规范化版本 **2**。旧基线可能丢失了 oneOf 重复分支或 enum 内层顺序，不能无损自动迁移。保留旧文件，从可信服务重新采集和审阅，再建立新基线。普通 CI 不执行迁移或批准。

基线读取拒绝重复键、错误版本和内容与指纹不一致。保存先在同目录校验临时文件再原子替换；不支持原子替换时失败并保留旧文件。审批通过协作锁及再次读取防止本工具的并发覆盖。`.write-lock` 是可保留的空协作锁文件，不应提交。

## 风险规则

规则是启发式线索，不能证明服务实现或返回内容安全。支持的 16 条规则如下；规则数量不是准确率指标。

| 规则 | 级别 | 检查内容 |
| --- | --- | --- |
| `HIDDEN_INSTRUCTION` | HIGH | 描述中包含已知指令覆盖措辞 |
| `INVISIBLE_CHARACTERS` | HIGH | 不可见字符与双向控制符 |
| `DESCRIPTION_SCHEMA_MISMATCH` | HIGH | 声称只读但存在写入参数线索 |
| `DUPLICATE_TOOL_NAME` | HIGH | 重复工具名 |
| `UNSAFE_SERVER_NAME` | HIGH | 服务名的异常字符 |
| `UNSAFE_TOOL_NAME` | HIGH | 工具名的异常字符 |
| `CROSS_TOOL_INSTRUCTION` | HIGH | 相邻工具拼接出指令覆盖措辞 |
| `ENCODED_PAYLOAD` | MEDIUM | 编码内容解码后的风险线索 |
| `CROSS_TOOL_DIRECTIVE` | MEDIUM | 描述指挥其他工具 |
| `SCHEMA_NO_PARAMETERS` | MEDIUM | 无参数且未关闭额外属性 |
| `SCHEMA_OPEN_OBJECT` | MEDIUM | 缺省或显式允许任意额外属性 |
| `DANGEROUS_PARAMETER` | MEDIUM | 参数名指向执行面 |
| `TOOL_SHADOWING` | MEDIUM | 名称与描述疑似冒充 |
| `SCHEMA_UNCONSTRAINED_STRING` | LOW | 缺少约束的字符串参数 |
| `PARAMETER_REACHES_ACCESS_SURFACE` | LOW | 文件或网络访问参数线索 |
| `SCHEMA_NO_REQUIRED` | LOW | 多参数缺少必填声明 |

## 输出与退出状态

`--out` 保存文本，`--json` 保存版本化结果，`--sarif` 保存 SARIF 2.1.0。JSON `reportVersion=3` 包含逐工具 tools 指纹、fingerprintsAvailable、errors 的类别／阶段／原因、采集与最终状态、checks 的静态风险／漂移执行状态、目标、完整工具面指纹、findings 和 diff。批量 JSON 使用 mode 与 targets 数组，并聚合各目标错误。正式 Schema 及字段含义见 [报告约定](docs/report-format.md)。

失败采集写 collectionStatus=FAILED，不伪造完整结果；部分目标完成时是 PARTIAL。采集完成后基线检查失败可同时是 COMPLETE 和 FAIL，已得到的工具指纹仍保留。JSON 记录最终输出状态。SARIF 的 invocation 标明是否完成扫描。终端显示转义控制字符，结构化文件保留经过 JSON 编码的值；错误诊断过滤已配置凭据。脱敏快照的 risk-only 报告明确标记指纹不可用。

| 退出码 | 含义 |
| --- | --- |
| 0 | 已完成检查且未达到阻断阈值 |
| 1 | 用法或配置错误 |
| 2 | 连接、初始化、请求超时或采集限制失败 |
| 3 | 静态风险达到阈值 |
| 4 | 未批准变化达到阈值 |
| 5 | 基线不可用、目标不匹配或审批指纹不符 |
| 6 | 报告输出失败，且没有更高优先级失败 |

默认风险阈值 HIGH，变化阈值 BREAKING。`--risk-only` 显式跳过漂移检查。多个目标同时失败时，优先报告基线、漂移、静态风险、连接、用法、输出错误；各目标详情仍保留。

连接与请求默认各 20 秒；采集总时间预算为连接超时加两倍请求超时，默认 60 秒。最多 100 页，拒绝重复游标；默认最多 1000 个工具，可用 `--max-tools` 调整；单定义 1 MiB、累计定义 16 MiB、规范化深度 64。解析前限制原始单消息 16 MiB、累计 JSON 消息 32 MiB；文件读取上限 32 MiB，JSON 最多 100 万 token。stdio 超时清理本次进程树，HTTP 取消响应流；具体限制及 SSE framing 边界见 [兼容说明](docs/compatibility.md)。

在线工具注解在带类型转换之前校验，错误 hint 类型直接拒绝，未知注解进入指纹与静态规则。旧在线证据中已被 SDK 丢弃的字段不能恢复；升级后出现的新路径必须重新审阅。稳定发行必须读取完整 Dependabot 告警，缺少权限或后续页读取失败均阻断，不再按旧 optional 开关降级。

## CI 与发行

仓库的 CI 和发布工作流共用最终产物验收，覆盖 Windows、Linux、stdio、HTTP、批准闭环、离线检查、失败报告和正式 SARIF Schema 验证。工作流配置完成不等于远端已经跑过；实际结果查看 Actions。

使用方的普通 CI 应读取受保护分支上经过审阅的基线，保留失败退出码，并在有有效报告时上传 SARIF。扫描失败不能因上传步骤而变为成功；来自 fork 的不可信配置不能获得秘密或在特权上下文启动进程。见 [接入与排错](docs/integration.md)。

```sh
# 在线生成 SBOM；Windows 使用 ./mvnw.cmd
./mvnw -B clean verify -Prelease-evidence
python -m pip install -r scripts/requirements-validation.txt
python scripts/verify_artifact.py
python -m unittest discover -s scripts -p 'test_*.py'
```

发行附件应包含已验收 JAR、校验和、依赖清单、SBOM 和构建来源记录。未通过实际标签产物验收前不标记稳定版。增量 shade 可能重复追加许可证；发行使用干净构建。校验和用于文件一致性，不能代替可信来源或签名。

## 覆盖限制与项目进度

本工具扫描声明面，尚未覆盖全部协议元数据、服务 instructions、资源、提示或调用结果；不承担持续运行时拦截。规则侧重点包括英文措辞，未验证任意语言的注入检测率。SDK 兼容范围见 [协议矩阵](docs/compatibility.md)。

同类项目中已有基线、审批、离线分析和 SARIF 能力，例如 [MCP Context Protector](https://github.com/trailofbits/mcp-context-protector)、[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) 和 [同名 TypeScript 工具](https://github.com/Wannavf/mcp-sentinel)。本项目侧重 Java 分发、可复现比较与团队 CI 审阅；未进行竞品准确率对测。

查看 [执行记录](docs/execution-status.md)、[设计约定](docs/decisions/0001-v06-trust-and-comparison.md) 和 [试点准备](docs/pilot-kit.md)。真实访谈、持续使用和付费结果需单独取证，不以自动测试代替。
