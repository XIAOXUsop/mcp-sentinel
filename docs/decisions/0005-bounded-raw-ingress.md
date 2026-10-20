# 有界原始输入与采集证据

2026-10-19，落实 R01 与 W08。保留 MCP SDK 2.0.1 的协议协商、HTTP session 和 JSON-RPC 调度；在 transport.unmarshalFrom 将 tools/list 转成 SDK Tool 之前，直接从未经过 ToolAnnotations 转换的 Map 建立本项目 ToolDefinition。严格检查已知字段类型，保留 annotations 的未知字段。SDK 类型仅承担调度，不作为原始工具证据。

原始单消息上限为 16 MiB，累计 JSON 消息上限 32 MiB；已有单工具 1 MiB、工具集合 16 MiB、100 页和总时间预算继续生效。HTTP 使用 SDK 的 maxResponseSize 在响应订阅阶段限制消息和 SSE 行；stdio 使用本项目拥有进程句柄的传输，在收字节和组行阶段限制输入，stderr 丢弃且限制累计字节。文件使用受限流读取，不先 readString 后检查。限制为硬上限，超限检查失败，不能形成基线。JSON 数值保留 BigDecimal、拒绝重复键与尾随文档。

stdio 关闭时先收集本次进程的后代，再终止并等待；超时强制结束。只处理本次启动的进程树，不扫描或终止其他用户进程。HTTP 取消与 SDK close 受时间限制。清理结果通过进程句柄和本地 HTTP 流的直接测试核对，不能仅凭连接返回失败判定清理完成。

旧在线基线保存的是 SDK 解码后的六字段证据，已丢失的字段不可恢复。新采集保留注解扩展，因此升级后可能出现以前未记录的路径；必须重新采集、审阅并批准，不能静默认为等价。合法定义的规范化版本与指纹算法不变。
