# 固定版本的外部实现验证

本目录只保存验证依赖与起始候选清单，不进入发行 JAR。manifest.json 的 candidate 是起始提交 917375e；每次运行的实际提交、JAR/SBOM 摘要以该次 summary/build-evidence 为准，不要求后续构建与起始包摘要相同。

需要 Java 21、Node 24.14.1、Python 3.12 和 Git。在独立 Python 虚拟环境安装：

```text
python -m pip install --require-hashes -r validation/interop/requirements-lock.txt
npm ci --prefix validation/interop --ignore-scripts --no-audit --no-fund
```

Python pins 是精确版本集合，lock 对每个版本包含 PyPI 发布文件 SHA256，Windows 专用 pywin32 有平台条件。npm package-lock 固定完整传递依赖和 SRI。维护更新时先审阅版本，再运行 scripts/lock_interop_python.py 更新摘要，普通 CI 不自动升级。Node 服务直接运行已安装入口，扫描时不临时联网安装。

完整 clean verify -Prelease-evidence 后运行：

```text
python scripts/verify_interop.py
python scripts/verify_approval_processes.py
python scripts/run_candidate_demo.py
python scripts/prepare_manual_corpus.py
python scripts/measure_scan.py --interop target/interop
```

Windows 使用 mvnw.cmd，其他平台使用 ./mvnw。JAVA_HOME 指向同一 JDK。远端作业为 .github/workflows/interop.yml，每个平台依次执行以上检查。

每个平台四个组合：Filesystem/stdio、Git/stdio、Playwright/stdio、Playwright/HTTP。独立原始客户端记录初始化和 tools/list，对照六个采集字段；缺省 title/description 为字符串空值，缺省 outputSchema/annotations 为对象空值。根级其他字段单列为覆盖边界。每组重复三次快照，再验证在线/离线报告和合成描述变化阻断。

collection-metadata.json 从生产 McpConnector 路径取得实际协商版本和指纹；referenceProtocol 与 sentinelProtocol 分别记录。该元数据留在验证证据中，报告 v3 和存储格式不改变。

Playwright 0.0.83 的 HTTP 允许列表比较完整 Host，包括端口；回环测试使用明确的 127.0.0.1:<port>，避免 403。该包内部 Playwright 依赖是 alpha 版本，已完整锁定；此处仅作为互操作对象。

参考客户端负责结束自己启动的服务；Sentinel 负责自己启动的 stdio 进程；独立 HTTP 服务由验证程序结束。过程记录追踪 PID 和应急清理前残留，应急清理不能把遗留资源的检查改成通过。

原始输出在 target，包含公开声明与本机路径。仓库只保存脱敏摘要，人工样本文本待再分发审查后再决定是否公开。
