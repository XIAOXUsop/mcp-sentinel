# 候选交付与验收

固定候选由 [Candidate delivery acceptance](https://github.com/XIAOXUsop/mcp-sentinel/actions/workflows/interop.yml) 生成。选择明确的提交和运行，不按最新成功记录替代当前候选。

## 交接入口

在对应成功运行中下载 `candidate-offline-kit`。其中 ZIP 是只需 Java 21 的体验包，`.sha256` 是 ZIP 校验和，`candidate.json` 是包外最终回执。先核对来源、提交与摘要，再解压阅读 `START-HERE.zh-CN.md`。

体验包包含已经测试的 Linux JAR，Windows 的实际 CLI、互操作、资源和审批检查使用同一份字节。Windows 源码单元测试与夹具单独编译，其临时 JAR 不作为交付产物。

完整工程证据在 `candidate-delivery` 工件：`linux/`、`win32/` 是原始平台证据，`sarif/` 是实际导入结果，`bundle/` 是不再修改的体验包，`consumption/` 是两平台消费记录。`candidate.json` 的 READY_FOR_HANDOFF 仅指该候选通过交付检查，稳定发布仍由独立策略和真实依赖告警检查决定。

使用与证据对应的干净源码检出，在相同受信 Actions 运行中执行：

```text
python scripts/check_candidate_evidence.py engineering --root evidence
python scripts/package_candidate.py --evidence evidence
python scripts/verify_candidate_package.py --bundle evidence/bundle --output evidence/consumption
python scripts/check_candidate_evidence.py candidate --root evidence
```

这些是维护者/CI 的工程入口，需要验证依赖；体验者只使用 ZIP 内的 Java 与操作系统终端。工程入口要求完整 CI 身份，普通本地环境不能冒充正式运行。候选最终回执位于 ZIP 外，消费测试不会修改已校验的 ZIP。

## 证据与限制

候选检查器校验运行/尝试编号、源码身份、文件摘要和必需场景集合。它要求两平台各 4 个互操作单元、10 组各 3+20 次资源观测、30 次连续扫描、4 个边界场景、7 个审批流程以及实际 SARIF 处理成功。未知、跳过、缺失、取消不算通过。各平台正常的静态风险提示不自动意味着互操作失败。

摘要用于发现替换和错配；证据来自受信工作流，摘要本身不是第三方签名。所有结果保留环境和测量方法，不能把共享 runner 之间的差异直接宣传为性能退化或提升。

自动消费验证在新的含中文/空格目录中解压，使用不含 javac/Maven/Python/Node 的 Java 运行时 PATH。五步退出码为 0、4、0、0、5，同时检查旧指纹拒绝且基线不变、缺 Java 时失败。它不能证明两位真实体验者已独立理解或完成操作。

## 保存与访问

| 材料 | 保存位置 | 处理边界 |
| --- | --- | --- |
| 源码、方法、脱敏状态摘要 | Git 仓库 | 不写令牌或团队原始数据 |
| 固定公开服务的原始声明、协议记录、人工开发声明 | Actions 完整证据工件；维护者本地验证目录 | 访问遵循仓库与 Actions 权限，不能称为仅本地；数据集再分发审查仍待完成 |
| 离线 ZIP | candidate-offline-kit | 仅项目生成的合成输入；不含原始公开服务声明或团队快照 |
| 失败记录 | 对应失败运行的诊断工件 | 不以成功重试覆盖历史失败 |
| 最终选定候选归档 | 维护者工作区交付目录 | 保存 ZIP、最终回执、SHA256 和远端元数据；记录下载失败/过期情况 |

工作流显式请求保留工件 90 天，实际受仓库设置限制。工件不可取得时不能只凭绿色 run 声称原始证据仍可复验。需要时重新形成候选，不改写旧身份。

## 发布与人工待办

[release-policy.json](../validation/release-policy.json) 当前 `stablePublicationAllowed=false`。缺失、格式错误或 false 都禁止稳定发布，即使工程检查全绿。仅后续明确用户决定可以支持修改该策略。正式路径仍需现场读取真实告警并处置阻断等级，不能用演练清单解除阻断。

N05 独立人工标注、N06 外部文档复跑由用户选择暂缓。恢复时沿用 [人工标注说明](validation/manual-labeling.md)、[候选接入记录](candidate-guide.md)和[试点材料](pilot-kit.md)；实际标签、复跑、访谈和试点保持真实计数。
