# 规范化保留 Schema 与实例的边界

2026-10-17 复审后，将已支持关键字的结构校验独立放在规范化之前，包含引用的文档也执行。dependentRequired 的非法重复项不能通过去重被修复。字段范围及方言限制见 [报告与校验约定](../report-format.md)。

选择上下文遍历，避免把实例数据中的 description、required 或数组当作 Schema 关键字。oneOf 重复项改变恰好一次匹配，必须保留次数；enum 外层可重排，但候选值内部保序。未知扩展只作保守对象键排序。

纯字节指纹容易因对象键重排产生噪声；试图判断所有 Schema 等价关系会带来无法覆盖的复杂性。这里选取明确支持的等价变换，其余变化保持可见。含引用的文档保留数组结构，防止引用索引随排序改变含义。

解析先保留 BigDecimal 精度，规范化不展开巨大指数。旧规范化可能丢失信息，所以版本提升为 2，旧文件不能通过无损迁移恢复。

验证入口：TrustRegressionTest、FingerprintAndBaselineTest，以及独立 JSON Schema 见证的 scripts/evaluate.py。生成探针不等于真实服务上的准确率评测。

enum 外层重复项与 required／type 的严格唯一性要求不同，不把它们一概当成同类语法错误；具体约束遵循 [JSON Schema 2020 12 验证规范](https://json-schema.org/draft/2020-12/json-schema-validation)。当前比较器不承担所有方言的完整合法性认证。
