# mcp-sentinel

> **MCP 工具面的 lockfile。** 把服务器的工具定义锁下来、提交进版本库，
> 让"配置被悄悄改了"像"代码被改了"一样出现在 diff 与评审里。

<div align="center">

![Java](https://img.shields.io/badge/Java-21-orange?logo=openjdk&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![offline](https://img.shields.io/badge/runs-100%25%20offline-2C5E2E)

</div>

## 它解决什么

MCP 的工具定义是**运行时从服务器拉取**的，而模型会照着这份定义决定调什么工具、传什么参数。
服务器在某次启动后把描述或 schema 改掉，调用方**看不到**——这就是 OWASP MCP03 说的
tool poisoning / rug pull：先发布人畜无害的定义取得信任，之后再悄悄换成有权限的那一版。

**下载**（一个可执行 jar，无需构建、无需安装）：

```bash
curl -LO https://github.com/XIAOXUsop/mcp-sentinel/releases/latest/download/mcp-sentinel.jar
java -jar mcp-sentinel.jar --help
```

> ✅ **v0.5.4 修掉了 v0.5.3 的三处问题**，下载最新版即可：
>
> | v0.5.3 的问题 | v0.5.4 |
> |---|---|
> | 内嵌 `jackson-dataformat-yaml` 停在 **2.18.4**，与同一次打包里的 databind / core（2.21.5）差 3 个 minor | 四个 jackson 构件统一到 **2.21 线**（`fef2da1`）；CI 新增一步**解开打好的 jar** 逐个核对，而不是检查 pom——pom 写对了不等于包进去的就是那个版本 |
> | 产物对外自称的版本号**漂了两版**：SARIF 里写 `0.2.0`、MCP 握手写 `0.5.1`，而 pom 早就是 0.5.3 | 版本号改成单一来源（pom 过滤进 `mcp-sentinel-version.properties`），并补了能问出这件事的 `--version`（`ff48373`） |
> | 配置里写 `"transport": "sse"` 会被**静默当成 streamable-http 收下**，于是配置错误报成了「连接服务器失败」（退出码 2）——把人引去排查网络 | 显式拒收，并告诉使用者该写什么（`35e010b`） |
>
> **v0.5.3 当时修的是 v0.5.2 的两处**（jar 内嵌 jackson-databind 2.19.0 → 2.21.5，
> 命中 5 条公告 2 HIGH；CI 注解报阻断阈值而非变更的实际分级），
> 那两条在 0.5.3 里就是好的，本次没有回退。
>
> v0.5.2 是「产物落后于 master」的实例：**它落后 6 个提交**，而 CI 当时全绿——它不查依赖。
> 现在 `release.yml` 里有两道发版闸（依赖告警 + tag 是否落后且动了构建配置），
> 这类情况不会再静默发出。详见下面「发版前的两道闸」。
>
> 这个工具存在的意义就是查出**别人**依赖里的这类问题，所以它自己的产物更不能含糊。
> 如果你确实要用更旧的版本：**别把它装进你的流水线**，或从源码构建
> （`./mvnw -B package`）。

> **v0.5.3 里那个 jackson 版本不一致是怎么发现的（2026-09-22，v0.5.4 已修）**
> ——它不在任何门禁的覆盖范围内，是解 shaded jar 逐个读 `pom.properties` 才看出来的：
>
> ```
> jackson-databind          2.21.5
> jackson-core              2.21.5
> jackson-annotations       2.21     ← 这个构件本来就是两段式版本号
> jackson-dataformat-yaml   2.18.4   ← 差 3 个 minor
> ```
>
> `jackson-dataformat-yaml` 是 `mcp-json-jackson2` 的传递依赖，不显式拉一把就会一直停在旧线上。
> **而上面那张表和 pom 的注释写的都是「内嵌 jackson-databind 2.21.5」**——
> 按那句话去核对的人，看到 databind 对了就会停下。这正是"看起来没问题"。
>
> v0.5.4 里它被显式拉到同一个 `${jackson.version}`（顺带把 snakeyaml 从 2.3 带到 2.5），
> 四个 jackson 构件统一在 **2.21** 线；并加了一道 CI 步骤**直接检查打出来的 jar**，
> 而不是检查 pom——pom 写对了不等于包进去的就是那个版本。

```bash
# 首次：锁下当前工具面，把生成的 mcp-sentinel.lock.json 提交进版本库
java -jar mcp-sentinel.jar lock --config mcp.json

# 之后每次 CI：与基线对比 + 查静态风险
java -jar mcp-sentinel.jar scan --config mcp.json

# 有意的变更被拦下时：批准它，并把基线推进到新状态
java -jar mcp-sentinel.jar scan --config mcp.json --accept-changes
```

配置格式与主流 MCP 客户端一致，可直接从现有配置复制。两种传输：

```jsonc
// ① stdio：起本地子进程（默认，与 Claude Desktop / VS Code / Cursor 的配置同形）
{
  "server": "my-server",
  "command": "java",
  "args": ["-jar", "my-mcp-server.jar"],
  "env": { "API_KEY": "..." }
}

// ② Streamable HTTP：扫远程端点
{
  "server": "my-remote-server",
  "transport": "streamable-http",
  "url": "https://mcp.example.com/mcp",
  "headers": { "Authorization": "Bearer ${MCP_TOKEN}" }   // 密钥用环境变量引用
}
```

> `transport` 只认两个值：`stdio`（缺省）与 `streamable-http`（可简写 `http`）。
> **`sse` 会被明确拒收，退出 1，并说清它是什么。**
>
> 它不能被当成 `streamable-http` 的别名：MCP 早期的 HTTP+SSE 与后来的 Streamable HTTP
> **不是一套协议**（握手方式不同）。把它当后者用，结果是对着一个 SSE-only 的服务器
> 按 Streamable HTTP 发请求、握手失败，报出来是「连接服务器失败」加一行目标 URL，
> **把人引到网络排查上去**，而真正的问题在配置里。
>
> 这条实测过（2026-09-22）：改之前 `"transport": "sse"` 得到退出 **2**；
> 同一份配置换成 `websocket` 反而得到退出 **1** 与「不支持的 transport」。
> **写得越像真的，报得越离谱。** 现在两者都退出 1。

> **请求头里的密钥用 `${环境变量名}` 引用，不要写明文。** 配置文件要提交进版本库，
> 而扫描器的输入恰恰是不可信的第三方配置——明文等于让"扫别人的服务器"顺手把自家令牌交出去。
> 引用了不存在的变量会在连接前直接失败（退出 1，按配置错误处理），
> **不会发一个空头出去**：空 `Authorization` 会以 401 失败，真正的原因（变量名写错）
> 就被埋进了一个看起来像"服务器拒绝"的错误里。

## 三件它比同类做得更细的事

锁定工具面这件事本身不新鲜。它的差异在这三处——每一处都对应一个**实测复现**的缺陷：

### 一、指纹是**语义**的，不是字节的

直接对 JSON 求哈希会把下面这些**语义等价**的情形判成变更：

| 改动 | 语义变了吗 | 旧版 |
|---|---|---|
| `required: ["q","limit"]` → `["limit","q"]` | 否，同一个 schema | **误报** |
| `enum:["fast","deep"]` → `["deep","fast"]` | 否，enum 是集合 | **误报** |
| `"maxLength": 100` → `100.0` | 否，同一个约束 | **误报** |
| 描述尾部多一个空格 | 否 | **误报** |

服务端用 Set / Map 的迭代顺序生成 `required` 是极常见的实现。**一个会因为无关重排而变红的
门禁，在被人信任之前就会被关掉**——所以 `SchemaCanonicalizer` 对明确是集合语义的关键字
（`required` / `enum` / `type` / `allOf` / `anyOf` / `oneOf`）排序去重、对数值做归一。

保守是刻意的：`prefixItems` 这类顺序有语义的保持原序，`enum` 值内部的空白不裁剪，
未知关键字一律不动——**宁可漏归一（退化成字节比较），不可错归一（把真实变更吃掉）**。

### 二、变更按 MCP 特有的风险轴分级

旧模型只有"变了 / 没变"，于是这三者输出完全一样，而它们的处置正好相反：

| 变更 | 级别 | 为什么 |
|---|---|---|
| 描述被改写 | **危险** | 描述就是投放给模型的指令面，投毒本体 |
| 加了一个**可选**参数 | **危险** | 扩大可传内容 = 给注入指令更多自由度 |
| 加了一个**必填**参数 | 破坏兼容 | 会打断所有调用方，但不是攻击 |

**注意这个判据与所有契约 diff 工具是反的。** oasdiff / buf breaking / graphql-inspector
的判据是"请求收窄、响应放宽会破坏客户端"，所以它们把"描述改了"判为 `info`——
Cisco 的 `mcpcontract` 规则文件里逐字写着
`rationale: "Descriptions are informational only and don't affect functionality"`。
那对 OpenAPI 文档是对的；对 MCP 是灾难性的。

共 **27** 类变更，分 `危险 / 破坏兼容 / 信息` 三档，`--fail-on-change` 可调（默认 `BREAKING`）。

> **第 27 类叫 `UNGRADED_SCHEMA_CHANGE`，它是 2026-09-22 补的一条兜底。**
> 分级器只枚举它认识的那几类关键字；没枚举到的改动原本**一条 `Change` 都不产生**，
> 而 `isClean()` 只看变更集是否为空——于是"分级器认不出"被当成了"没有变化"：
>
> ```
> 嵌套 object 里加一个参数        指纹变了 → 变更 0 条 → 「与基线一致」退出 0
> 参数加 "const"                 指纹变了 → 变更 0 条 → 同上
> items 从 integer 放宽成 string  指纹变了 → 变更 0 条 → 同上
> 顶层加 allOf                    指纹变了 → 变更 0 条 → 同上
> ```
>
> rug pull 的完整形态（"名字没变、参数多加一层"）只要写在已有 object 参数的嵌套里就报绿。
> 现在不变量被钉死了：**指纹变了 ⇒ 至少一条变更**，认不出改了什么就按 DANGEROUS 记一条，
> 出口是人工核对后 `--accept-changes`。宁可让人多看一眼，也不能说"一致"。

### 三、审批可以继承，而且**不会**被滥用

变更指纹 = 变更类型 + 工具 + 序号 + 说明 + **变更后的内容摘要**，写进基线的 `acceptedChanges`。
于是：

- commit A 批准过的变更，在 commit B 里仍然算已批准——**审批不会因为"改了别的东西"而失效**；
- 但**批准了「描述改成 Beta」不等于批准「改成 Gamma」**。如果指纹只绑定变更类型，
  第二次改动会自动继承第一次的批准——而"批准之后悄悄再改一次"恰好就是 rug pull 的形态。
  端到端测试专门盯着这一条。

这套 change fingerprint 的做法在 oasdiff 里已被验证，搬到 MCP 工具面是第一次。

## 检测规则

| 规则 | 级别 | 抓什么 |
|---|---|---|
| `HIDDEN_INSTRUCTION` | HIGH | 描述里夹带面向模型的指令性措辞 |
| `INVISIBLE_CHARACTERS` | HIGH | 零宽 / 双向控制字符 |
| `DESCRIPTION_SCHEMA_MISMATCH` | HIGH | 描述自称只读，schema 却含写入语义参数 |
| `SCHEMA_NO_PARAMETERS` | HIGH | 声明为 object 却没有任何属性 |
| `DUPLICATE_TOOL_NAME` | HIGH | 工具名重复——以名字为键的存储会互相覆盖 |
| `UNSAFE_SERVER_NAME` | HIGH | server 名含规范外的字符（可夹带换行与控制字符） |
| `UNSAFE_TOOL_NAME` | HIGH | tool 名含规范外的字符（可夹带换行与控制字符） |
| `CROSS_TOOL_INSTRUCTION` | HIGH | 一句话被拆到两个工具的描述里 |
| `ENCODED_PAYLOAD` | MEDIUM | base64 串**解码后**是指令性措辞 |
| `CROSS_TOOL_DIRECTIVE` | MEDIUM | 描述点名本工具面内的另一个工具 + 指令性措辞 |

| `SCHEMA_OPEN_OBJECT` | MEDIUM | `additionalProperties: true` |
| `DANGEROUS_PARAMETER` | MEDIUM | 参数名指向**执行面**（`command` / `exec` / `sql`） |
| `TOOL_SHADOWING` | MEDIUM | 与既有工具名称相近且描述雷同 |
| `SCHEMA_UNCONSTRAINED_STRING` | LOW | 字符串参数无取值约束（按工具聚合） |
| `PARAMETER_REACHES_ACCESS_SURFACE` | LOW | 参数名指向**访问面**（`path` / `file` / `url`） |
| `SCHEMA_NO_REQUIRED` | LOW | 多参数却无必填约束 |

> **上面这张表有多少行、有多少条规则，由 `RuleInventoryTest` 对着代码数一遍钉住。**
> 2026-09-22 之前这两个数是错的：规则表 **15 行而实现有 16 条**
> （`UNSAFE_SERVER_NAME` 与 `UNSAFE_TOOL_NAME` 被并进了一行），
> 变更类**写了 22 而实现有 26 类**。两处都是自洽的——表 15 行、正文也写 15——
> 所以肉眼看不出来，只有去数代码才发现。

**每条发现都给出"为什么有风险"而不只是"命中了规则"。** 安全告警必须可解释，
否则使用者只会学会忽略它。

规则执行前会对文本做 Unicode 归一（NFKC + 去零宽 + 西里尔/希腊同形字折回拉丁）——
`"Ignore аll previous instructions"` 里那个 `а` 是 U+0430，肉眼与拉丁 `a` 完全一样，
不归一则一条都不命中。

## 命令行

```
mcp-sentinel lock --config <配置> [--out <基线文件>]
mcp-sentinel scan --config <配置> [选项]
mcp-sentinel --version
```

> `--version`（或 `-V`）打印**这个产物自带的版本号**，以 0 退出。
> 它存在的理由值得写下来：版本号原先在两处手写死（SARIF 的 `driver.version` 是 `0.2.0`、
> MCP 握手的 `clientInfo` 是 `0.5.1`，而 pom 早就是 `0.5.3`），**漂了两个版本没人发现**
> ——因为没有一条命令能问出"这个 jar 是哪一版"。现在版本只有一个来源
> （pom 的 `<version>` 经资源过滤进来），`--version` 是它的出口，也是能端到端验的那一步。

| 选项 | 说明 |
|---|---|
| `--baseline <文件>` | 基线位置（默认 `mcp-sentinel.lock.json`） |
| `--risk-only` | **显式**声明只跑静态风险规则，不做漂移检测 |
| `--out <文件>` | 把报告另存一份 |
| `--sarif <文件>` | 输出 SARIF 2.1.0 |
| `--fail-on LEVEL` | 风险规则在哪个级别阻断（默认 `HIGH`） |
| `--fail-on-change LEVEL` | 工具面变更在哪个级别阻断（默认 `BREAKING`） |
| `--accept-changes` | 批准本次变更并写回基线，并打印**审批摘要**（见下）。没有变更可批准时不改动文件 |
| `--timeout N` | 连接超时秒数（默认取配置里的 `timeoutSeconds`，否则 20） |
| `--help` | 用法 |

两种传输共用同一套检测语义：规则、指纹、基线都不认识"传输"这个概念，
分叉只在连接层的一个方法里。换传输不该改变任何一条检测结果。

| 退出码 | 含义 |
|---:|---|
| 0 | 通过 |
| 1 | 用法或配置错误 |
| 2 | 连不上目标服务器 |
| 3 | 命中达到阈值的风险规则 |
| 4 | 工具面有达到阈值的**未批准**变更 |
| 5 | **基线不可用**（缺失 / 不是普通文件 / 不可读 / 损坏 / 版本不兼容 / 内容不全） |
| 6 | 输出产物写入失败（`--out` / `--sarif`） |

风险与漂移同时出现时返回 `4`——漂移是这个工具的核心信号。四种情况会各自输出一行
`::error::`，不会因为先判漂移就把风险项的注解吞掉。

### 批准之后能审什么

`--accept-changes` 会改写基线文件。如果它只回一句"已接受 1 处变更"，评审者在 PR 里
看到的就是一个锁文件的 diff——他看不出被批准的是「加了个可选参数」还是
「描述被换成了另一段话」，而这两者的安全含义正好相反。所以它会把三件事打出来：

```
本次批准的变更（写进基线的 acceptedChanges，后续提交里继续算已批准）：
  [DANGEROUS] DESCRIPTION_CHANGED        lookup       3f9a2b7c1d5e6f00 → a1b2c3d4e5f60718
      工具描述被改写（描述会进入模型上下文，是投毒的本体）
      变更指纹 8c1f0a2b3d4e5f60718293a4b5c6d7e8
  按级别统计: {DANGEROUS=1}

工具面指纹   : 3f9a2b7c1d5e6f00 → 9c8b7a6f5e4d3c2b
基线写回时间 : 2026-09-18T04:36:04.119520700Z
```

**没有变更可批准时，它一个字节都不写。** 重写会让 `generatedAt` 刷新一次，
于是 `git status` 里多出一条改动、diff 里只有一行时间戳——评审者看到"工具面好像变了"，
实际什么都没变。让"没变"看起来像"变了"，和让"变了"看起来像"没变"，破坏的是同一个契约。

**边界**：静态风险发现**不参与批准**。它们描述的是当前工具面本身有问题，
而不是「和上次不一样」——批准基线不会、也不该让它们消失。
摘要里会单独列出仍然存在、仍会阻断的发现，避免"批准过就没事了"的误解。

### fail-closed：门禁不会"安静地失效"

`scan` 默认要求基线可用。基线读不到时它**退出 5，不会退化成"只跑风险规则然后返回 0"**。

这一条看着啰嗦，但它是这类工具最容易被绕开的地方——不是被攻击者绕开，而是被一次
操作失误绕开：忘了拷 lock 文件、CI 缓存被清了、`--baseline` 路径写错、基线被别的工具
覆写成了半截 JSON。这些都会让漂移检测悄悄关掉，而旧行为给出的是一次**干净通过**。
**没有人会去修一个显示绿色的门禁。**

因此：

- 基线校验发生在**连接服务器之前**——本地文件已经不可用，就没必要再去启动一个不可信的
  子进程；
- 失败时说明怎么恢复（先 `lock`，或显式 `--risk-only`），但**绝不自动重建基线**：
  基线本身就是"当初批准的是什么"的证据，自动重建等于让证据自愈；
- 真正只要静态规则时，用 `--risk-only` 把这件事**说出来**，而不是让它作为默认行为发生。

`--sarif` 同理：写不出来意味着这次扫描的结果永远不会出现在 PR 上，
所以它是退出 6，而不是"打一行 stderr 然后返回 0"。

## 接入 CI

```yaml
- name: Lock the MCP tool surface
  run: java -jar mcp-sentinel.jar lock --config mcp.json --out mcp-sentinel.lock.json
  # 把 mcp-sentinel.lock.json 提交进版本库

- name: Scan and gate
  run: java -jar mcp-sentinel.jar scan --config mcp.json --sarif results.sarif

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

上面的 `scan` 就是默认的 fail-closed 形态：基线读不到会直接失败，而不是静默跳过漂移检测。
只有在你明确不需要漂移检测时才写 `--risk-only`。

`--sarif` 输出 SARIF 2.1.0，位置指向**仓库内真实存在的文件**（有基线时指向基线，
并精确到该工具所在的行号），因此 GitHub Code Scanning 会正常显示。
> **如实说明**：行内注解需要真实的 GitHub 仓库与 Code Scanning 权限才能端到端验证，
> 本仓库没有那个条件。能验证的是位置符合官方规则 GH1005（相对 URI 或 `file:` 方案、
> 有 `startLine`）、`partialFingerprints` 齐备（否则每次运行新建 alert 而非更新）、
> 以及每条结果的 `ruleIndex` 都指回已声明的规则。

## 与现有工具的关系（以及我不假装的事）

同赛道上更成熟的项目：**[snyk/agent-scan](https://github.com/snyk/agent-scan)**（原 Invariant
`mcp-scan`）、**[cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)**、
**[trailofbits/mcp-context-protector](https://github.com/trailofbits/mcp-context-protector)**、
**riseandignite/mcp-shield**。

| | snyk/agent-scan | cisco/mcp-scanner | mcp-sentinel |
|---|---|---|---|
| 语言 | Python | Python | **Java** |
| 检测引擎 | 15+ 类规则 + **云 API** | YARA + LLM + 行为分析 | 16 条确定性规则 |
| 扫描范围 | 全机器配置 / skills / MCP | tools / prompts / resources / 源码 / 依赖 | **仅工具定义** |
| 运行方式 | 需上传组件信息到云 API | 需 LLM 与 VirusTotal Key | **完全离线** |
| 工具面基线 / 漂移 | ❌ | ❌ | ✅ |
| 变更语义分级 + 审批继承 | ❌ | ❌ | ✅ |

**必须承认的**：前两者在规则深度与扫描范围上明显更强。它们能识别"这条描述像恶意"，
但识别不了"这条描述上周不是这样"——反过来也一样。
**它们与 mcp-sentinel 互补，不互相替代。**

**而"锁定工具面"这件事本身已经至少被 12 个实现做过**（Vercel AI SDK 甚至把
`fingerprintTools` / `detectToolDrift` 做进了 SDK），所以本项目的主张不是"我们有 lockfile"，
而是**"我们把 lockfile 做对"**——语义规范化指纹、MCP 特有的分级判据、内容绑定的审批继承，
这三件目前没有一家同时做到。

## 设计取舍

**为什么指纹与规则不依赖 MCP SDK。** 连接是易变的（SDK 版本、传输方式），检测语义是稳定的。
分开之后绝大多数测试可以完全离线跑，换 SDK 版本也不会改变"什么算风险"。

**为什么用 `mcp-core` + `mcp-json-jackson2` 而不是 `mcp` 聚合包。** 聚合包会拉入
`mcp-json-jackson3`，而 Jackson 2 与 Jackson 3 的 `com.fasterxml.jackson.annotation`
包同名不同代，无法共存于同一 classpath（实测报 `NoClassDefFoundError: JsonSerializeAs`）。
踩过的坑，写在这里省得你重踩。

**为什么基线存完整定义而不只是指纹。** 只有指纹算不出"加了可选参数"与"加了必填参数"
的区别——两者都只是"指纹变了"，而安全含义正好相反。它同时是"当初批准的是什么"的证据。
代价是文件变大（500 工具约 200–400KB）。

**为什么连接失败返回结果而不是抛异常。** 扫描器本身要能在目标不可用时给出可读诊断——
"哪个命令、什么错误"，而不是甩一段堆栈。

## 已知限制

- **不做运行时。** 只读工具定义，不执行工具、不拦截 `tools/call`、不扫源码与依赖。
  参数注入、越权调用这类运行时问题不在覆盖范围内。
- **跨工具拆分只抓相邻片段。** 用 Shamir 秘密共享之类方式把指令拆成互不连续的多个片段
  （ShareLock, arXiv 2606.27027 报告平均 ASR 94.1%）**抓不到**——那需要理解片段间的
  重构关系，不是拼接文本能解决的。
- **同形字折叠表不完备。** 只覆盖常见的西里尔 / 希腊 / 全角替换；罕见的同形字符仍可绕过。
- **不支持 `cwd`。** MCP SDK 的 `ServerParameters` 没有暴露工作目录（实测其 Builder 只有
  `command` / `args` / `env`）。与其假装支持，不如在这里说清楚。
- **HTTP 传输不做 OAuth 授权流程。** 只发配置里写好的静态请求头（值可用 `${VAR}` 引用环境变量）。
  需要交互式授权的服务器，请先用别的工具取到令牌再注入环境变量。
- **`--timeout` 在两种传输下含义不同**：stdio 是请求超时，HTTP 是**连接**超时。
  远程服务器可能连得上但响应很慢——那种情况下表现为请求超时，不是退出码 2。
- **基线存完整定义，文件会变大**（500 工具约 200–400KB）。这是语义分级能力的必要成本。
- **规范化规则升级会造成一次全量假变更。** 基线里记了 `schemaVersion`，
  版本不符时会明确提示"请重新 lock，这不是攻击"，而不是让人误判。
- **`DESCRIPTION_CHANGED` 默认属危险档，所以文档改动也会让 CI 红。** 这是 MCP 特有的
  正确判据（描述即指令面），出口是 `--accept-changes`。

## 构建与测试

```bash
./mvnw verify      # 127 项测试
```

含**真实端到端用例**：起 MCP 服务器子进程 → 走 MCP 协议拉取工具面 → 检查退出码。
端到端服务器用 `RawMcpServer`（手写的 JSON-RPC 回放器）而不是官方 SDK——
要构造的形态（重名工具、带换行的 server 名）用 SDK 起服务时跑不起来，
而真实威胁模型里**服务器是不可信方**。

### 可复现构建

```bash
./mvnw clean package -DskipTests   # 连做两次，产物 sha256 应当完全相同
```

这个 jar 是发到 GitHub Release 的，所以「你下载到的这个 jar 是不是从这份源码构建出来的」
应当能被**哈希**回答，而不是只能靠信任。让这句话成立的是两件事：

- **时间戳固定**（pom 里的 `project.build.outputTimestamp`）。不固定的话，jar 里每个
  条目的时间就是"构建那一刻"，同一份源码在任何两个时刻构建出的字节都不同。
  加之前实测：两次干净构建产物**大小相同（6098536 字节）但 sha256 不同**——
  只看大小会以为没问题。
- **构建工具钉住**（`.mvn/wrapper/maven-wrapper.properties` 里的 Maven 版本）。
  时间戳只保证"同一台机器两次相同"，跨机器还需要构建工具一致——否则
  `META-INF/MANIFEST.MF` 里的 `Created-By` 就不一样。这一条是同族仓库踩出来的：
  `desensitize-spring-boot-starter` 在一台用系统 Maven 3.3.9 的机器上构建，
  MANIFEST 写的是 `Created-By: Apache Maven 3.3.9` 还多一行
  `Built-By: <构建机器的用户名>`，而 CI 构建的是 `Maven JAR Plugin 3.5.0`。

代价是 jar 里的时间戳不再反映真实构建时间。对一个要被验证的产物来说，这是划算的。

### 发版前的两道闸

打 tag 会触发 `.github/workflows/release.yml`，但**不是打了就一定发**——
发之前 `scripts/release_preflight.py` 要过两道：

| 闸 | 查什么 | 为什么单独一道不够 |
|---|---|---|
| 一 | 仓库里还有 `high`/`critical` 的开放依赖告警 → 拒绝 | 它查的是**默认分支当前**的依赖图 |
| 二 | 这个 tag 落后默认分支，且落后的提交动过 `pom.xml`/`mvnw`/`gradle` 配置 → 拒绝 | 它保证"产物 = CI 在默认分支上验过的那份" |

**两道都要，是因为 v0.5.2 恰好落在两道之间**：它的 jar 里是 jackson-databind 2.19.0，
而 master 上早已升到 2.21.5——只查仓库告警的话，看到的是**干净的 master**，
不是那个已经发出去的产物。闸二会把这个 tag 落下的 6 个提交逐条列出来，
其中就有 `b180618 fix(deps): jackson-databind 2.19.0 -> 2.21.5`。

两条设计约束：

- **查不动 ≠ 通过。** HTTP 401/403/404、响应不是数组、级别字段不认识、git 历史取不到——
  一律拒绝发布。这些情况在日志里的表现和"没有告警"完全一样，把它们当成通过，
  就正好复刻了 v0.5.2 那次"看起来没问题"。
  > ⚠️ **但「拒绝」要拒得对**：这条闸最初建在一个 Actions 的 `GITHUB_TOKEN`
  > **够不到**的接口上。2026-09-20 在 ctxpress 上实测：
  > `GITHUB_TOKEN` + `security-events: read` → **403 `Resource not accessible by integration`**；
  > 匿名 → 401；本地 PAT → 200。也就是说 **Dependabot 告警接口只认 PAT / GitHub App token**
  > （`security-events` 那个权限管的是 code scanning，不是 Dependabot）。
  > 一道永远查不动、于是永远拒绝发布的闸，和没有闸是一回事——它只会被绕过。
  >
  > 所以 workflow 现在：**优先用 `secrets.PREFLIGHT_TOKEN`（PAT）**；
  > 没配时给闸一加 `--alerts-optional`，降级为**大声告警后放行**。
  > 降级**只覆盖"平台不让这个 token 查"**（401/403/404）——脚本自己的故障
  > （状态码文件没写出来、响应不是数组、字段缺失、5xx）**一律照样拒绝**，
  > 否则等于开了个「把检查弄坏就能绕过」的后门。真读到高危告警时，
  > `--alerts-optional` 也管不着，照样拦。
- **不依赖 OWASP dependency-check。** 它要 NVD 数据，没有 API key 时一次全量更新
  要跑几十分钟且频繁 429（姊妹项目 amlagent 的依赖扫描因此永远跑不完，
  而**常年红的门禁等于没有门禁**）。Dependabot 告警是 GitHub 侧算好的，
  一个请求就能拿到，所以这道闸放在 release 而不是 CI——代价被限制成"这次先别发"。

闸一和闸二各自有一组回归用例（`scripts/test_release_preflight.py`，CI 里跑）。
反向验证过：拿掉「级别不认识 → 拒绝」、把 403 放行、拿掉「落后者动了构建配置 → 拒绝」
三处守卫，分别会让 2 / 1 / 2 条用例变红。降级开关另有 5 条用例，
其中最要紧的一条是「真读到高危告警时 `--alerts-optional` 管不着」——
否则这个开关就成了"把红变绿"的后门。

Release 里还会附一份 `DEPENDENCIES.txt`（`mvn dependency:list` 的输出）：
闸只认识**已知**的 CVE，一个还没进 Dependabot 库的问题它看不见；而使用者拿到一个 6MB
的 shaded jar 本来无从知道里面是什么版本——上面那条 jackson 版本就是解压 jar、
读 `pom.properties` 才确认的。对比两个版本的这份清单，也正好是"这次升级动了什么"。

开发中由实测发现并修复的问题（均已补回归用例）：

1. `format: "date"` 未被当作约束，误报正规的日期参数
2. 名字相似度用固定 Jaccard 阈值，漏报 `read_file → read_file_v2` 这类加后缀的影子工具
3. `mcp` 聚合包与 Jackson 2 的注解包冲突
4. **重名工具让漂移检测被完全静默绕过**——基线以工具名为键，改其中一个等于没改，退出码 0
5. **指纹把语义相同的定义判成变更**——`required`/`enum` 换序、`100` vs `100.0`、描述尾随空格
6. **三个字段完全不在覆盖内**——翻转 `destructiveHint`、改 `outputSchema`、改 `title` 均无感
7. **服务端字符串未消毒**——server 名带换行可伪造报告行、注入 `::notice::`、让 SARIF 被拒收
8. **SARIF 位置用了 `mcp://` 自定义 scheme**——GitHub 按 GH1005 不显示这些结果
9. **同形字绕过**——西里尔 `а` 替换拉丁 `a` 即失效
10. **`TOOL_SHADOWING` 把 `search_1` 与 `search_10` 判成影子工具**
11. **最弱一条规则对良构工具面 100% 命中**——500 个正常工具产生 1500 条 LOW
12. **`--out` 在 `scan` 下被静默忽略**、漂移判断吞掉风险项的 `::error::` 注解
13. **基线读不到时静默退化成纯风险扫描并以 0 退出**——一次漏拷的 lock 文件表现为一次干净通过
14. **`--sarif` 写入失败只打一行 stderr 就继续**，最终可能以 0 退出；而 SARIF 正是 CI 消费的产物
15. **拼错子命令会真的去执行配置里的命令**——`frobnicate` 先按配置把服务器子进程拉起来，
    握手失败后报"连接服务器失败"退 2。一个本地拼写错误变成了对外部进程的调用，
    而退出码 2 把人引到网络排查上去。配置的来源恰恰是不可信的，能不起就不起
16. **`lock` 静默忽略 `--sarif` / `--fail-on` / `--fail-on-change`**——它不扫描、不判风险、
    不比对漂移，这些选项没有对应行为。脚本以为 SARIF 已经落盘、阈值已经生效，实际什么都没做
17. **没有变更可批准时 `--accept-changes` 仍重写基线**——`generatedAt` 被刷新一次，
    `git status` 多出一条改动，diff 里只有一行时间戳。评审者看到"工具面好像变了"，
    实际什么都没变。基线 diff 是这个工具唯一能被评审的东西，不能掺这种噪音
18. **CI 注解报的是阻断阈值，不是变更的实际分级**——「描述被改写」是 DANGEROUS 档，
    注解却写成「达到 BREAKING 级别」（那只是 `--fail-on-change` 的默认值）。
    同一个工具在同一次运行里给出了两个不同的严重度：报告正文写 `[DANGEROUS]`，
    注解说 `BREAKING`。**低报**会让人按错误的严重度处置。
    之所以长期没被发现，是因为原有断言只查 stdout 的报告正文，
    而注解走 stderr——**两边从没被放进同一个断言里对比过**
19. **发出去的产物带着已修的漏洞。** v0.5.2 的 jar 里 jackson-databind 是 2.19.0
    （5 条告警，2 HIGH），而 master 上早已升到 2.21.5。**当时 CI 全绿**——
    它根本不查依赖；而 Dependabot 告警是仓库级的，查的时候看到的是已经修好的 master。
    干净的是 master，不是那个产物。修法是发版前加两道闸（见上文「发版前的两道闸」），
    并且把 **403/404「查不动」也判为拒绝**——它和"没有告警"在日志里长得一样

## License

[MIT](LICENSE) © 2026 XIAOXUsop
