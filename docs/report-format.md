# JSON 报告 v3 与输入校验约定

本地候选的 `reportVersion` 为 **3**。v2 的逐工具指纹、结构化错误、指纹可用性和变化路径继续保留；v3 增加每个目标的 `checks.staticRisk` 与 `checks.drift`，避免把“尚未执行”解释为“已检查且零发现”。基线格式仍为 3、快照格式仍为 1、规范化版本仍为 2；合法定义的指纹算法不变。

正式结构约束保存在 [scan-report-v3.schema.json](../schemas/scan-report-v3.schema.json)。[历史 v2 Schema](../schemas/scan-report-v2.schema.json)供旧证据读取；消费方先检查 reportVersion，再按对应 Schema 解析。`scripts/verify_artifact.py` 使用独立 Python 验证器校验实际 JAR 的成功、失败、批准及多目标报告，并反向确认缺失指纹、错误阶段或检查状态会被拒绝。

## 逐工具证据

`tools` 包含本次已经采集的每个工具，按名称稳定排序；同名条目使用 `occurrence`（从 0 开始）区分。`name` 保留原始名称，`fingerprint` 为完整的 64 位小写十六进制 SHA256。

`fingerprintsAvailable=true` 表示来自原文工具面；对脱敏快照的显式 risk-only 扫描，该值为 false，工具和工具面指纹为空字符串，不把脱敏内容的哈希冒充原始证据。快照文件自身仍使用原有的 REDACTED 标记。

`diff.paths` 保存结构变化，`diff.changes[].paths` 保存该项解释或阻断所覆盖的实际 JSON Pointer 路径。工具名称和出现序号共同定位路径；空字符串表示整个新增／删除工具。每个实际结构路径都必须对应至少一个解释或保守阻断项，不能因已经存在 INFO 变化而跳过检查。

## 失败与采集状态

`errors` 的每个对象包括 `category`、`phase`、`message`。失败原因使用受控显示转义；已知配置凭据、环境变量值、参数值和 URL 从目标诊断中过滤。不能将未知远端报文视作可信日志。

| phase | 发生位置 |
| --- | --- |
| ARGUMENTS / INPUT_VALIDATION | 命令参数或输入约束 |
| CONFIG_READ / CONFIGURATION | 配置读取或凭据引用解析 |
| SNAPSHOT_READ / SNAPSHOT_VALIDATION | 快照格式、工具定义或脱敏证据限制 |
| INITIALIZE / COLLECT_TOOLS | 协议初始化或工具采集 |
| CLEANUP | 连接或本次资源清理无法完成 |
| BASELINE_READ / BASELINE_TARGET | 可信基线读取或目标不匹配 |
| APPROVAL / BASELINE_WRITE | 已审阅指纹不符或基线无法写回 |
| POLICY_CHECK | 漂移或静态风险达到阻断阈值 |
| REPORT_WRITE | 报告输出失败 |

`collectionStatus` 只描述采集是否完成。快照已经读入后，基线不可用或目标不匹配可以同时表现为 `collectionStatus=COMPLETE`、`status=FAIL`、退出 5；不丢弃已经得到的工具指纹，也不把“采集完成”描述成“漂移检查完成”。错误快照本身无法读入时为 FAILED。

`checks.staticRisk` 为 COMPLETE 或 NOT_RUN；`checks.drift` 还可以是 SKIPPED（显式 risk-only）。基线读取或目标验证失败时，两项均 NOT_RUN；静态风险与漂移完成后因策略阻断时，两项仍 COMPLETE。文本报告显示未执行阶段和具体错误，SARIF invocation 保留失败状态。各字段不能互相替代。

批量报告 `mode=MULTI_TARGET`，目标项保持独立 tools、errors 和退出状态。顶层 errors 聚合目标错误并附 targetId；输出失败单独记录。`outputErrors` 保留 TEXT／SARIF／JSON 种类标记。SARIF 的 executionSuccessful 对基线、参数或采集失败为 false。

## 校验与规范化分别执行

校验在指纹计算前运行，含 `$ref` 的文档也不跳过校验；它不解析或下载外部引用。

- 注解的 readOnlyHint、destructiveHint、idempotentHint、openWorldHint 必须为布尔值，title 必须为字符串。
- 在线 tools/list 的原始字段在 SDK ToolAnnotations 转换之前校验；字符串、数值、null 均不能转换为合法 hint。未知注解保留进入指纹与静态规则，stdio 与 HTTP 使用相同入口。旧在线快照丢失的扩展不能恢复；升级后重新采集、审阅新路径。
- Schema 的 required、type 和 dependentRequired 字符串数组检查条目类型和唯一性；type 名称还必须是标准 JSON 类型。dependentRequired 可以为空对象，其依赖列表可以为空数组。
- 已识别的 Schema 映射、子 Schema、组合数组、标量约束及描述性字段检查结构和值类型。保留既有 draft-07 tuple-form items 形式；此检查不承担完整方言认证、正则表达式有效性证明或引用解析。
- const、default、enum 候选值、examples 内容和未知扩展中的业务键不按 Schema 关键字验证。未知扩展仍保守比较。enum 外层重复值与 required 的严格唯一性要求不同，不将其一概拒绝。

类型与字符串集合的约束依据 [JSON Schema 2020-12 验证规范](https://json-schema.org/draft/2020-12/json-schema-validation)。本地校验范围不能替代完整 Schema 验证器；不确定的工具面变化继续交给保守阻断和人工审阅。
