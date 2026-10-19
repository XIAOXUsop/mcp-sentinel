# 2026-10-19 代码检视

检视提交：`637818543fcbe1c529beafc72f6c19e429fc0b1d`。

[完整报告与后续操作](audit.md)记录了 8 项已复现问题及修复验收条件。结论为 **G1 重新打开，稳定发行条件尚未满足**。本目录提交的是检视结果；问题尚未修复，既有 CI 成功不能代替这些反例的验收。

`review-summary.json`、`review-probe-results.json`、`extra-probe-results.json` 是上述提交的历史验收记录。摘要中的工作区干净、未修改代码和未推送描述的是检视发生时的状态，不代表本目录后来没有提交。`evidence/` 保存独立实例见证、原始合成响应、快照和关键错误报告，不含真实凭据。

## 复跑

需要 Java 21、Python 3.12，以及仓库的验证依赖。在所检视提交上构建，或将当时源码放在独立 checkout，再使用此目录脚本。后续修复可能改变预期结果，运行结果会如实记录，不能将本目录的历史结果当作新版本结果。

在仓库根目录执行：

```sh
python -m pip install -r scripts/requirements-validation.txt
./mvnw clean verify -Prelease-evidence
python docs/reviews/2026-10-19/repro/run_review.py
python docs/reviews/2026-10-19/repro/extra_probes.py
```

Windows 使用 `mvnw.cmd`；`JAVA_HOME` 应指向 JDK 21。新输出全部写入 `target/review-2026-10-19/`。脚本启动本地合成 stdio 服务，不访问被扫描的生产服务。

176 项 Java、31 项 Python 回归以及正式产物校验通过，与本轮反例失败同时存在。完整构建日志和 JAR 保存在本地交付目录；仓库保留摘要、可复现输入及脚本。JAR SHA256：`2c9bd17e9bb45923c7c69aa90a77e25017150948b2bd56707c6889bc1e13a3c8`。
