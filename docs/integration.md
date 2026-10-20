# 团队接入与排错

离线 PR 示例见 [trusted-offline-pr.yml](../examples/trusted-offline-pr.yml)。扫描器、策略和已批准基线从 base.sha 检出并构建，候选分支只提供快照数据，不执行候选配置命令或代码。示例使用 pull_request 和只读权限，两个 checkout 都不保留凭据。

候选快照仍是待审数据，不证明实际服务按该声明运行；来源与对应关系需要可信采集或人工审阅。使用方应审阅自己的构建方式和固定数据路径。示例保留扫描失败，再上传报告文件，没有将 artifact 上传当作 GitHub Code Scanning 的 SARIF 导入。

scripts/verify_approval_processes.py 使用真实独立进程验证竞争、中断、可信/候选基线对照和输出失败。中断点为校验完成的临时文件和完成的原子替换，不泛化为断电保证。常规验证作业为 contents:read；独立 SARIF 导入作业另有 security-events:write，结果以该次实际处理状态为准。

## 可信基线

选择服务、权限角色和环境后指定稳定别名。先审阅配置及服务来源，再执行 lock；检查生成文件并提交受保护分支。对不同角色使用独立别名和基线。v0.5 文件保留用于历史审阅，不能被新版本静默接受。

普通 CI 只运行 scan。不要在每轮扫描前 lock，也不要把 --accept-changes 放入无人审阅的流水线。PR 内更新基线时，需要明确的基线审阅流程；不能只依赖候选分支自带的锁文件证明它已经被批准。

## 保留扫描失败状态并上传报告

以下是使用方工作流的核心步骤，前提是 JAR、配置与基线已经由可信流程准备好。它适合受保护分支的在线监测；fork PR 使用离线快照或先做人工可信性判断，不能获得密钥或执行任意配置命令。

```yaml
- name: Scan trusted target
  id: sentinel
  shell: bash
  run: |
    set +e
    java -jar tools/mcp-sentinel.jar scan --config mcp.json --baseline mcp-sentinel.lock.json --json report.json --sarif report.sarif
    code=$?
    echo "exit_code=$code" >> "$GITHUB_OUTPUT"
    exit "$code"
- name: Upload SARIF when available
  if: ${{ !cancelled() && steps.sentinel.outcome != 'skipped' && hashFiles('report.sarif') != '' }}
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: report.sarif
    category: mcp-sentinel/trusted-target
```

扫描步骤不使用 continue-on-error，因此上传后仍然保留失败。调用方按 GitHub 官方要求配置 contents:read 和 security-events:write；私有仓库另核对 Code Security 可用性。批量报告含多个独立 run，每个目标有独立 automationDetails.id。

## 审阅和批准

1. scan 保存 JSON 与快照；核对具体工具、变化和角色。
2. 使用 JSON 中 baselineFingerprint、surfaceFingerprint 的完整值执行批准。
3. 任一预期不一致时重新采集、审阅。不得为了通过而用新值自动替换预期。
4. 检查基线 diff 和审批上下文，提交审核。历史审批不会自动授权不同快照。

退出 3 说明静态风险仍在；批准只影响漂移，不移除风险规则。退出 5 表示漂移或批准无法可靠完成，不能降级成通过。退出 6 时查看 outputErrors 和目标路径；已有更高优先级失败时，输出错误仍记录但不会替代原退出码。

目标别名、传输、命令或 HTTP origin 改动会影响身份。路径、查询、环境变量值、参数和权限角色不从秘密自动推断；角色与环境由你使用别名区分。切换角色后必须审阅是否需要新基线。

## 发行与回退

CI 与 Release 共用 verify.yml，双平台验证成功后发布工作流下载已验收的 Linux JAR，不再重建。打包脚本核对标签版本、提交与 JAR 摘要，并附 CycloneDX SBOM、依赖清单与来源记录。来源 JSON 是构建记录，不是独立签名。

若新版验证失败，保留旧工具与旧基线成对使用或暂时转人工审阅。已知存在漏检的旧版不能被称为安全恢复。正式发行前要以该标签的远端双平台结果为准。
