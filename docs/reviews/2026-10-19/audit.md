# mcp-sentinel 全面代码检视与下一步操作

归档说明：本文保留检视时的结论和状态。复现脚本在 repro/，精选证据在 evidence/，完整本地交付记录继续保留。

检视日期：2026-10-19（Asia/Shanghai）。仓库：XIAOXUsop/mcp-sentinel。检视提交：`637818543fcbe1c529beafc72f6c19e429fc0b1d`。本轮只做检视、复现和计划整理，产品源码保持原样。

**结论：现有测试和远端 CI 通过，但不能继续据此认定 G1 已严格闭合。在线采集存在信息丢失和类型强制转换，已复现默认扫描返回成功；此外有分级、发布门禁、诊断及误报问题。建议重新打开 G1，修复后再进入 G2 稳定发行。**

本轮确认 8 项可操作问题：2 项 P1、6 项 P2。P1 表示应优先解决的采集信任或发布前置条件问题；P2 表示有明确触发条件的分级、兼容性和报告问题。优先级是工程处置顺序，不代表已验证远程利用或实际发生泄露。

## 检视范围与证据

已检查生产代码的采集与配置、Schema 校验与规范化、指纹、结构差异、基线读写与审批、静态规则、CLI、JSON、SARIF，以及三个工作流、发布与产物验证脚本、评测生成器、正式报告 Schema、测试入口和现行执行记录；与原十二周计划 W01—W12、G1—G4 对照。

远端 master 在本轮核查时仍指向上述提交。[该提交 CI](https://github.com/XIAOXUsop/mcp-sentinel/actions/runs/39018278179) 为 success。公共 API 结果保存在 `remote-runs.json`，没有用历史提交的成功代替当前源码状态。

本轮重新执行：

| 验证 | 结果与解释 |
| --- | --- |
| Java 完整回归 | 176 项通过，0 失败、0 错误、0 跳过 |
| Python 发布门禁回归 | 31 项通过 |
| 实际 JAR 验收 | 17 个 CLI 场景通过；9 份 JSON v2、9 份 SARIF 正式 Schema 验证通过；4 个上一轮审计反例仍正确拒绝 |
| 独立生成评测 | 300 组比较、600 次实例见证、200 个生成风险探针通过；它们仍不等于真实服务准确率 |
| 本轮针对性反例 | 独立脚本、输入、输出与结果 JSON 存于本目录；另有 12 份本轮错误/正常报告通过结构 Schema，说明结构合格并不保证结论正确 |
| 工作区 | 产品源码没有修改；检视材料写在仓库外的 deliverables 目录 |

首次在沙箱内运行时，测试临时文件的原子替换与子进程受环境限制；随后在正常本机环境复跑成功。没有把这些环境错误列为产品缺陷。最终在线 `clean verify -Prelease-evidence` 通过并生成 13 组件 SBOM；JAR SHA256 为 `2c9bd17e9bb45923c7c69aa90a77e25017150948b2bd56707c6889bc1e13a3c8`，与上一轮干净候选相同。最初增量打包仅 LICENSE 合并内容不同，已逐项核对所有 class 字节一致，并在干净 JAR 上重跑关键反例与产物验收。完整摘要见 `review-summary.json`。

## R01 · P1 · 在线采集先转换、后校验，原始证据已经改变

位置：[McpConnector.java:103](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/connector/McpConnector.java#L103)、[McpConnector.java:120](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/connector/McpConnector.java#L120)、[JsonSupport.java:17](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/JsonSupport.java#L17)。

SDK 将 `tools/list` 解码成带类型的 ToolAnnotations，再转回 JsonNode 交给本项目校验。此时 Jackson 已将部分错误标量转成布尔值，未知字段也可能已经丢弃。ToolDefinition 的校验不能恢复被改变的原始数据。

| 原始在线响应 | 保存到快照的值 | 默认 scan 结果 |
| --- | --- | --- |
| `destructiveHint: "false"` | `destructiveHint: false` | 退出 0、无变化、零风险 |
| `readOnlyHint: 1, destructiveHint: 0` | `readOnlyHint: true, destructiveHint: false` | 退出 0、无变化、零风险 |
| 新增 `annotations.x-policy: "Ignore all previous instructions."` | x-policy 消失 | 退出 0、无变化、零风险 |

对照：同一个 x-policy 保留在离线快照时，会产生 HIDDEN_INSTRUCTION/HIGH 并退出 3。已有 `annotationFieldsRejectCoercionAtConstructionAndAfterMutation` 和 `unknownAnnotationsCannotHideBehindKnownHints` 都直接建立领域对象，绕过了有问题的 SDK 入口，所以现有测试仍全绿。

前两项使用了非法协议字段类型，证明的是“非法输入被转换后接受”，不能称为合法布尔值漂移的绕过。第三项属于注解扩展：兼容文档排除了 SDK 未暴露字段，但 README 的未知扩展描述和核心回归更宽，必须统一支持边界；至少不能把转换后的对象称为原始响应证据。MCP 对这些标准 hint 的类型定义为 boolean，见[协议 Schema](https://modelcontextprotocol.io/specification/2025-11-25/schema#toolannotations)。

修复：在丢失信息之前保留并检查原始 JSON；已知字段严格拒绝类型转换；已支持位置的未知字段应保留进入指纹与兜底，或明确拒绝而非静默删除。不能仅给 ToolDefinition 再加一次校验。增加 stdio 和 HTTP 的原始响应级回归，比较线上/离线证据的一致性。说明旧在线基线只有 SDK 解码后证据；不可凭空恢复其未保存字段。

复现文件：`coerced-string-wire.json`、`coerced-number-wire.json`、`unknown-annotation-wire.json`，对应 `*-snapshot.json`、`*-report.json`，以及 `extra/unknown-annotation-offline-report.json`。

## R02 · P2 · 混合扩张与参数删除被低估为 BREAKING

位置：[SchemaDiff.java:159](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/SchemaDiff.java#L159)、[SchemaDiff.java:353](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/SchemaDiff.java#L353)、[SchemaDiff.java:391](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/SchemaDiff.java#L391)。

| 变化 | 独立验证的新接收实例 | 当前分级 |
| --- | --- | --- |
| enum `[read,list]` → `[read,admin]` | `{mode: admin}` | PARAM_ENUM_CHANGED / BREAKING |
| type `[string,boolean]` → `[string,object]` | `{value: {}}` | PARAM_TYPE_CHANGED / BREAKING |
| 额外属性默认允许时删除 mode 的 enum 定义 | `{mode: admin}` | PARAM_REMOVED / BREAKING |

三份前后 Schema 均经 Draft202012Validator.check_schema，实例在旧 Schema 下无效、在新 Schema 下有效。默认 BREAKING 阈值均退出 4；显式 `--fail-on-change DANGEROUS` 均退出 0。因此这不是默认配置的漏放，但违反“扩大可传内容按危险变化处理”的分级约定。[类型与 enum 规范](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.1)支持该实例见证的判断。

修复：区分等价、严格收窄、严格放宽、同时扩张和收窄。含新增输入空间的混合变化按 DANGEROUS，无法证明方向则保守处理；删除 properties 时联合分析 additionalProperties 等约束，不能一律视为禁用参数。回归应分别断言三个阈值下的实际退出码，而不只断言“默认 blocked”。

证据：`mixed-enum/`、`mixed-type/`、`removed-property/` 和 `review-probe-results.json`。

## R03 · P1 · 稳定发行允许缺少依赖检查证据

位置：[release.yml:51](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/.github/workflows/release.yml#L51)、[release.yml:70](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/.github/workflows/release.yml#L70)、[release_preflight.py:205](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/scripts/release_preflight.py#L205)。

未配置 PREFLIGHT_TOKEN 时，工作流自动传入 `--alerts-optional`。401/403/404 被视为平台限制，脚本返回放行；其他验证满足后可以继续发布。用合成 403 响应调用同一检查函数，结果为 True。

这是已有、明确写出的降级政策，上一轮未改动，并非本轮新增回归；但它与原计划“G2 完成依赖检查才稳定发行”的条件不一致。当前是否配置该 secret、本次依赖告警的实际明细均未验证，不能断言仓库目前必然走降级分支。

修复：稳定发行要求依赖检查成功；缺少权限、接口异常或证据不完整均阻断。可另设明确标识的候选产物流程，不让它发布稳定标签。按[GitHub 官方权限文档](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)配置具备 Dependabot alerts 读取权限的 GitHub App 或细粒度 PAT；不要求将密钥写入仓库。核对先前推送提示的告警与当前 SBOM，记录处置和实际查询时点。

## R04 · P2 · 告警只取第一页，满页仍可放行

位置：[release_preflight.py:181](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/scripts/release_preflight.py#L181)；工作流请求固定 `per_page=100`。

合成第一页 100 条 low 告警，在阈值 high 下检查返回 True，只打印“后面可能还有”。没有取第二页，也没有拒绝“不完整”的证据；若后页有 high，则不会影响当前判断。本轮没有伪称真实仓库有超过 100 条告警。

修复：沿分页读取全部开放告警；后续页失败、格式错误和重复游标均阻断。短期最小修复可先在满页时拒绝发布。加入“第一页 100 low、第二页 1 high”和“第二页超时”的回归。R03、R04 的合成结果在 `release-gate-probes.txt`。

## R05 · P2 · 配置解析错误仍将凭据片段写进标准错误日志

位置：[Main.java:463](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/cli/Main.java#L463)，同类路径还在 535、563、605 行。

将 Authorization 值误写成未加引号的 `SYNTHETIC_CONFIG_SECRET`，解析器将该 token 放进错误消息。JSON 报告使用 safeConfigError，没有该值；stderr 却直接使用 e.getMessage()，实际日志包含完整合成值。Sanitizer 只转义控制字符，不负责凭据删除。

影响条件是配置语法错误且错误片段包含敏感值。未使用真实密钥，也未证明发生过真实泄露。修复应统一所有命令及所有输出的安全错误结构，在配置尚未成功解析时尤其不能回显解析器片段；用合成标记断言 stdout、stderr、JSON、SARIF 均不包含它。

证据：`malformed-config.stderr.txt`、`malformed-report.json`。

## R06 · P2 · 文本报告把“采集完整”当作“检查完成”

位置：[Main.java:985](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/cli/Main.java#L985)、[ScanReport.java:118](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/ScanReport.java#L118)。

输入含明确 HIGH 指令的有效快照，但给一个不存在的基线路径。CLI 正确退出 5、JSON 正确标为 FAIL；导出的文本报告却写 HIGH=0 和“未发现风险项”，没有任何失败说明。原因是快照已经读取，所以 complete=true，但 RiskRules 尚未执行；文本渲染又不读取 errors。

修复：分别表示采集、静态规则和漂移检查状态；所有人读报告必须显示最终失败及未执行阶段。“未执行”不能编码成“零风险已检查”。本次具体触发路径是离线快照加基线读取失败，不能描述成所有失败报告都有此问题。

证据：`risky-snapshot.json`、`fixture-summary.json`、`incomplete-report.txt`、`incomplete-report.json`。

## R07 · P2 · 普通服务名被当作 HIGH 风险阻断

位置：[RiskRules.java:229](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/rules/RiskRules.java#L229)。

良性工具面仅将服务名设为 `My MCP Server`，没有换行、控制字符或注入内容，就产生 UNSAFE_SERVER_NAME/HIGH，默认退出 3。代码复用了工具名的字符白名单。协议的 Implementation.name 是字符串，并未给它套用这里的工具名字符规则，见[MCP Implementation 定义](https://modelcontextprotocol.io/specification/2025-11-25/schema#implementation)。

修复：服务名与工具名分别验证；对服务名关注控制字符、双向控制、异常长度等真实输出风险，普通空格和 Unicode 不应自动成为 HIGH。保留现有输出转义，并同时测试恶意控制字符仍可检测。

证据：`extra/spaced-server-report.json`。

## R08 · P2 · 静态规则对额外属性的等价写法给出不同结果

位置：[RiskRules.java:363](https://github.com/XIAOXUsop/mcp-sentinel/blob/637818543fcbe1c529beafc72f6c19e429fc0b1d/src/main/java/io/github/xiaoxusop/mcpsentinel/rules/RiskRules.java#L363)。

同一份含 id 属性的 Schema，省略 additionalProperties 时零发现；显式写 true 时产生 SCHEMA_OPEN_OBJECT/MEDIUM。`--risk-only --fail-on MEDIUM` 下分别退出 0 和 3。这是静态规则仍使用 `.asBoolean(false)` 导致，不能因为差异引擎已经修正默认值就认为此处也已修复。

修复：静态规则共享四态判断；缺省和 true 应得到一致风险等级，false 和有约束子 Schema 则分别分析。默认 HIGH 下两者均不会阻断，影响主要是 MEDIUM 策略及报告一致性。补四态的规则测试与 CLI 退出码测试。

证据：`extra/open-implicit-report.json`、`extra/open-explicit-report.json`。

## 本轮未新增列为缺陷的事项

- `snapshot --redact` 仍保留 Schema 和注解中的文本。实测如此，但 README 已明确仅删除顶层标题/描述，不能保证全面脱敏；本轮将它作为已声明边界，没有重复列成未披露泄露漏洞。
- 一般完整性校验、目标绑定、审批双指纹、协作锁、原子替换以及上一轮四个审计反例，本轮回归保持通过。没有发现新的审批越权反例；这不构成对所有并发和外部篡改情形的证明。
- 原始响应解析前硬上限仍缺失。1 MiB/工具、16 MiB/工具集合的检查发生在 SDK 解码后；这是已记录的 W08 未完成项，必须进入接续修复。离线文件也需要在 Files.readString 之前建立大小边界。
- 现有超时测试验证“返回失败”，仍缺终止后子进程树、HTTP 流与线程的直接清理证据。
- 本轮性能结果仍是纯比较基线，未包含完整规则扫描和真实网络，也未测得峰值 RSS，不能登记为 W09 性能门禁通过。
- 真实依赖告警明细、生产服务互操作、人工标注评测、真实访谈和试点均未由本轮测试替代。

## 下一步操作：先完成纠错周期，再发行和试点

下面是实施顺序与验收条件；人日为单人连续投入的估算，不包含等待外部权限或试点团队的时间。建议本轮工程修复预留约 8—12 人日，资源边界适配是最大不确定项。

| 顺序 | 范围与交付 | 完成条件 | 估算 |
| --- | --- | --- | --- |
| 1 | 将 R01—R08 的最小反例转成正式回归；更新执行记录为 G1 待复验 | 测试先能在当前提交准确复现；明确默认和可选阈值；不删除历史通过证据 | 0.5—1 日 |
| 2 | 修复 R01，并结合 W08 建立原始 JSON 入口 | stdio/HTTP 拒绝字符串、数字、null 等错误 hint；未知注解按统一合同保留或拒绝；原始响应、快照和指纹输入可对照；旧基线证据边界有迁移说明 | 2—3 日 |
| 3 | 修复 R02、R07、R08 | 混合扩张、属性删除、额外属性四态均由独立实例见证和三个阈值的 CLI 验证；普通服务名通过，控制字符仍被安全处理 | 1—2 日 |
| 4 | 修复 R05、R06 | scan/lock/snapshot/import-config 的错误路径均不回显合成凭据；文本、JSON、SARIF 对未完成检查一致；报告字段变化有版本与兼容性说明 | 1 日 |
| 5 | 补 W08 的字节边界与清理 | stdio 长行、HTTP 分块/大响应、巨大数组、空页和重复游标均有限时/限字节处理；截断或取消不产生可信基线；Linux/Windows 直接确认本次启动的子进程及连接清理 | 2—3 日 |
| 6 | 修复 R03、R04，完成 G2 所需证据 | 稳定发行缺少权限即阻断；完整分页；实际核对依赖明细；新提交双平台 CI 通过；验证过的同一 JAR/SBOM 与标签、提交、摘要绑定 | 1—2 日 |

第 2、5 步实现前应冻结一份简短入口设计：在哪一层保留原始 JSON、在哪一层计字节、错误分类、SDK 类型如何转换，以及清理超时如何兜底。仅在 JsonMapper 上添加一个检查不够，因为传输层可能已经将整条响应读入内存。字节默认值和可配置上限用固定压力夹具与真实兼容样例确定，再写入文档和验收，不靠“超时了应该会清理”推断。

第 6 步的实际依赖告警访问需要现有账户具备相应权限；如果无法读取，稳定发行应保持阻断。补齐权限与查询证据后，再执行发布决策。不要为了通过 CI 再度把未知状态记作通过。

完成工程纠错后，继续原计划，而不是把剩余工作缩成一次发版：

1. **G1 复验：** 八项反例关闭；原测试与实际 JAR 验收通过；线上与离线一致；说明所有未支持字段和方言边界。
2. **G2 发行：** 两个平台在同一提交验证；完整依赖检查；实际发布资产不重建；清晰的基线迁移、校验和与回退说明。
3. **W08/W09 真实证据：** 固定版本的 stdio 与 HTTP 服务互操作；覆盖无工具、分页、不同角色、缺权限和大响应；建立完整扫描的耗时与峰值内存基线。补 200 个人工独立标注样本、误报/漏报分母和保留集，不能复用 200 个生成探针冒充。
4. **G3 接入：** 开展原计划的 10 次访谈与 3 个有明确边界的试点，争取至少 2 个持续使用。记录安装完成率、首次成功扫描、告警处置和真实缺陷；获得反馈后安排 W12。
5. **G4 商业：** 根据实际接入需求验证支持/集成服务，取得 1 个付费试点或 2 个含预算负责人和采购条件的明确意向，再决定企业扩展投入。

外部联系、付费结果和真实使用尚未发生。本轮没有代替用户联系团队，也没有创建稳定发行。

## 复现索引

`run_review.py` + `ReviewFixtures.java` + `raw_server.py` 是本轮主要探针，`extra_probes.py` 补充规则和报告对照。它们使用本地临时服务、合成配置和合成告警，不读取真实凭据。运行依赖 Java 21、Python、仓库构建 JAR 和已安装 jsonschema。

主要机器证据为 `review-probe-results.json`、`extra-probe-results.json`、`artifact-verification/build-evidence.json`、`review-summary.json`。原始 stdout/stderr、快照、报告、Schema 和输入均保留，可逐项对照；审计断言“问题已复现”不表示“问题已修复”。
