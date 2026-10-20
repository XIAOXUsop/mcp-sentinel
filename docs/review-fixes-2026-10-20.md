# 2026-10-19 检视问题修复与验收

记录日期：2026-10-20。接续 [八项检视发现](reviews/2026-10-19/README.md)。检视材料已独立提交为 `9f4971f`，此后按反例、修复、实际产物验证的顺序实施。原检视及旧构建证据保持历史状态。

## 修复闭环

| 发现 | 实现 | 对应验证 |
| --- | --- | --- |
| R01 在线证据转换/丢失 | 在 SDK Tool 转换前读取原始 Map；已知字段严格校验，未知注解保留；证据与具体响应实例绑定，拒绝缺失/重复消费或过多待处理响应 | RawIngressTest 对 stdio/HTTP 的四类 hint 检查字符串、数字、null；未知注解在两种传输保留。EvidenceCorrelationTest 验证交错响应不串用证据；实际 JAR 验证线上/离线指纹一致 |
| R02 混合变化分级 | 取值和类型同时扩张/收窄时按危险处理；移除属性时结合额外属性、patternProperties 和必填条件保守判断 | ReviewRegressionTest 对三份独立见证案例逐个验证 INFO/BREAKING/DANGEROUS 阈值；实际 JAR 读取原审计夹具并在 DANGEROUS 阈值退出 4 |
| R03 缺少依赖检查可发布 | 稳定工作流必须有告警读取权限；旧 optional 输入不再授权缺少证据的发布 | Python 回归覆盖 403、缺文件、错误响应和未知级别；工作流移除自动降级。本轮依用户选择保持稳定发布阻断，未核实真实告警明细 |
| R04 只读第一页 | 新脚本逐页读取，拒绝重复告警/异常后续页；完整回执绑定文件摘要和条数；无回执的满页拒绝发布 | 第二页 high、第二页超时、满页后空页、重复页、错误回执和缺少凭据测试 |
| R05 配置错误回显凭据 | 四个命令统一使用受控配置诊断，不回显解析器片段 | scan/lock/snapshot/import-config 的合成敏感标记均不出现在 stdout/stderr；实际 JAR 负向场景验证 |
| R06 未执行写成无风险 | 文本显示具体失败和未完成状态；JSON v3 增加 checks.staticRisk 与 checks.drift；保留 collectionStatus 的独立含义 | 含 HIGH 指令的快照在缺基线时退出 5；文本不显示零风险结论；JSON 两项 NOT_RUN；SARIF invocation 失败 |
| R07 普通服务名误报 | 服务显示名与工具标识分开检查，普通空格和 Unicode 不自动触发 HIGH；控制字符和异常长度仍受限制 | 普通/恶意服务名回归；实际 JAR 对含空格服务名返回成功 |
| R08 额外属性默认值不一致 | 静态规则与差异引擎共享四态定义；缺省、true 与空 Schema 均按允许任意值处理 | 对缺省、true、false、子 Schema 和空 Schema 验证；实际 JAR 在 MEDIUM 阈值下前两项阻断、受限两项通过 |

## W08 资源边界

stdio 在组行阶段计 UTF-8 字节，不先无限读取后再校验；标准错误丢弃且有累计上限。写入在独立调度线程执行，避免服务器停止读输入时把请求超时与清理锁一起阻塞。进程句柄由本项目持有，先关闭追踪到的后代，再关闭父进程，超过短暂等待则强制结束；清理不完整时扫描失败。

HTTP 使用 SDK 的响应订阅限制，覆盖固定长度、分块响应和 SSE；解析前累计 JSON 消息预算。文件使用受限流，拒绝过大的文件和读取期间增长。JSON 限制 token 数、字符串、字段名和嵌套深度。具体上限、SSE framing 与进程隔离边界见 [兼容说明](compatibility.md)及 [入口决策](decisions/0005-bounded-raw-ingress.md)。

ResourceIngressTest 直接验证超大 stdio 行/stderr、文件、JSON 数组、累计消息、固定/分块 HTTP 响应、SSE 断开，以及超时后的父/子 PID 已结束；另验证大游标请求在服务不再读输入时仍能超时并清理。它们是本地受控夹具，不代替生产服务互操作或操作系统沙箱。

## 本地验收

Corretto 21.0.10、Windows 11、Python 3.12：

- 在线干净 `clean verify -Prelease-evidence`：191 项 Java 测试通过，0 失败、0 错误、0 跳过；生成 13 组件 CycloneDX SBOM。
- Python 发布门禁：37 项通过。
- 最终 JAR：33 个命令行场景通过，其中 16 个复验本轮发现；24 份 JSON v3 和 24 份 SARIF 通过正式 Schema。三个无效报告反向样例被拒绝；旧审计的四个输入反例仍被正确拒绝。
- 生成评测：300 组比较、600 次独立实例见证、200 个规则探针通过；仍不计为人工标注真实准确率。
- 三份工作流通过 actionlint 结构/表达式检查；没有将此记为 shellcheck 或 pyflakes 通过。

本地最终 JAR SHA256：`861984f9c91e9fbaf1f594dfd2f9a87f93c6a311b333cb302d4961207c35e3bc`；SBOM SHA256：`409ab92823d74d983f763dcb8b726e99e32aa9027219bd43b9187af515fbb31f`。

实际 JAR、SBOM 摘要、日志和报告保存在工作区 `deliverables/mcp-sentinel-fixes-2026-10-19/`，最终产物验收位于 `final-artifact-verification/`。本地产物证据保留 local-working-tree 来源，不冒称远端构建。提交后的 Linux/Windows 结果查看 [master CI](https://github.com/XIAOXUsop/mcp-sentinel/actions/workflows/ci.yml?query=branch%3Amaster)；最终推送回执绑定具体提交和 run。

## 迁移与剩余门槛

JSON 消费方迁移到 reportVersion=3 和 [v3 Schema](../schemas/scan-report-v3.schema.json)。基线格式 3、快照格式 1、规范化版本 2 不变。旧在线证据里已经丢失的注解扩展无法恢复；新采集产生的新路径必须审阅和批准，不能凭原文件推断历史原文。

本轮完成八项工程修复和受控资源回归。真实依赖告警验收及稳定发布依用户选择继续阻断；没有创建发行标签。真实服务互操作、完整扫描峰值内存、人工独立标注、访谈、试点和商业证据仍按原计划推进，不能由这些生成测试替代。
