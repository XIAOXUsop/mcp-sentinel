# 2026-10-20 下一阶段执行与证据索引

本记录承接 [下一阶段计划](../next-stage-plan-2026-10-20.md)，未把工程工作量估算当作已经投入的人日。起始提交为 917375e；后续候选新增实际协商版本元数据，报告和存储格式保持原契约。

| 任务 | 已有实施及本地结果 | 尚需的验收 |
| --- | --- | --- |
| N01 | 固定起始候选、三个服务版本、完整 npm SRI/Python SHA256 锁、可重复启动说明 | 后续每个候选继续单独绑定产物和提交 |
| N02 | Windows 四组通过，工具数 14/12/25/25；三次采集、独立原文、在线/离线、合成漂移及清理；两类客户端实测协商均为 2025-11-25 | 两平台合计八单元以对应提交 interop 工作流为准 |
| N03 | 起始候选完成十组各 3+20 次测量和连续 30 次运行；新候选四类边界拒绝及 PID 清理通过 | 新候选在远端两平台独立 runner 内完整顺序测量并保留原始数据 |
| N04 | 两独立审批进程、中断前后旧/新完整文件、可信/候选基线、过期批准、输出失败，共七项通过；提供可信 PR 示例 | 双平台过程结果按工作流核对；GitHub Code Scanning 的实际 SARIF 导入未执行 |
| N05 | 准备标注说明、来源/分组规则和 20 个未标注开发声明 | 独立人工标签、分歧处理与标注试运行等待参与者；不能登记为已完成 |
| N06 | JSON v3 迁移说明、五步实际 JAR 演示和访谈/试点记录流程已准备 | 两名未参与实现者实际复跑等待参与者 |
| N07 | 192 项 Java 回归、37 项 Python、33 个分发 JAR 场景通过；24 JSON/24 SARIF；远端工作流已定义 | 最终提交、检查结论和 run 链接以推送验收回执登记 |
| N08 | 首批开发声明来源可追溯，未产生人工标签 | 200 样例、10 来源、独立复核、保留组和统计报告未完成 |
| N09/N10 | 访谈与两周试点的记录及验收口径已准备 | 10 次访谈、3 个独立团队试点及持续使用证据未产生 |
| N11 | 保持阻断 | 真实依赖告警未核实，当前用户发布阻断未解除 |

## 可复跑入口

依赖与命令见 [validation/interop/README.md](../../validation/interop/README.md)。

- 互操作：target/interop/summary.json，四个 cell 各自的 reference/wire.json、reference-tools.json、collection-metadata.json、快照、报告和 process.json。
- 性能：target/performance/summary.json、逐次 measurement.json/samples.json、continuous.json 和 boundaries/summary.json。原生扫描进程峰值与采样进程树最大值分别记录。
- 审批：target/approval-processes/summary.json 及每个实际进程的命令、退出与文件摘要。
- 演示：target/candidate-demo/summary.json 和五份实际 v3 报告。
- 人工评测：target/manual-corpus/samples.json 当前 humanLabels=0，全部 development，无保留集指标。

远端运行入口为 [interop.yml](https://github.com/XIAOXUsop/mcp-sentinel/actions/workflows/interop.yml)；每次运行的 commit、JAR/SBOM、依赖锁摘要在相应证据中对应。只有同一候选的实际成功结果才可计为该项通过，工作流文件存在不等于已通过。

## 实施中发现并处理的验证问题

Playwright HTTP 首轮 403 源于该版本比较完整 Host，而非仅主机名。核对已安装源码后用明确的回环主机加端口解决，未放开任意主机，也未修改产品以掩盖错误。

演示脚本初版漏传审批参数、边界脚本初版将用法/连接退出码对调，均按真实 CLI 契约修正并复跑。这些属于验收工具问题，不计作产品漏洞。起始候选及首轮互操作失败保存在工作区 deliverables/mcp-sentinel-next-stage-2026-10-20，原始失败不改写成通过。

## 门槛

G1 新增元数据已补真实 HTTP 降级协商回归；完整正确性仍限于已声明覆盖。G2 继续阻断。G3/G4 没有用户或商业结果可计入。人工标注、外部复跑、访谈和试点必须由实际参与者产生证据，不能由本轮自动测试替代。

当前自动工作流仅 contents:read，保存 SARIF 文件并校验 Schema；尚未执行 Code Scanning 导入，不能将 artifact 上传算作导入成功。候选阶段不据此宣称 N04 的外部集成子项全部完成。
