#!/usr/bin/env python3
"""用**官方 SARIF 2.1.0 schema** 校验 mcp-sentinel 的产物。

为什么需要这么一条：

`SarifWriterTest` 里那些断言全都在"取节点然后比内容"，而 `path()` 取不到东西
会返回 missing node、`.get(0)` 返回 null——**结构错位与内容缺失长得一模一样**。
于是 `result.logicalLocations`（该在 `result.locations[]` 底下）与
`properties.tags` 写成了裸字符串这两处，在本地测试全绿的情况下活了很久，
而 README 那句话一直是"输出 SARIF 2.1.0"。

实测（2026-09-22）：修之前一次含 finding + 漂移的扫描报 **10 个 schema 错误**；
官方的 code scanning 对不合规产物的处理是**整体拒收**，
也就是本地全绿、上传之后什么都没有。

用法：
    python scripts/check_sarif_schema.py <文件.sarif> [...]
    python scripts/check_sarif_schema.py --selftest

退出码：0 = 全部通过；1 = 有错误（明细打到 stderr）；2 = 用法/环境问题。

不需要网络：schema 与脚本放在一起（`scripts/sarif-2.1.0-schema.json`）。
这一点是刻意的——**校验器自己依赖网络，就等于把"能不能验证"交给了别人**。
"""
from __future__ import annotations

import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "sarif-2.1.0-schema.json")

# 一份最小但**会踩到那两处结构**的样例：结果里带 locations / logicalLocations /
# properties，规则上带 property bag。缺任何一处都测不出东西。
MINIMAL_SAMPLE = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "mcp-sentinel",
                    "version": "0.0.0",
                    "rules": [
                        {
                            "id": "TOOL_REMOVED",
                            "name": "TOOL_REMOVED",
                            "shortDescription": {"text": "工具被移除"},
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {"tags": ["security"], "precision": "high"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "TOOL_REMOVED",
                    "ruleIndex": 0,
                    "level": "warning",
                    "message": {"text": "工具面变更"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "mcp-sentinel.lock.json"},
                                "region": {"startLine": 7},
                            },
                            "logicalLocations": [
                                {"name": "ghost", "fullyQualifiedName": "mcp://demo/ghost",
                                 "kind": "resource"}
                            ],
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": "0123456789abcdef"},
                }
            ],
        }
    ],
}


def load_schema():
    if not os.path.exists(SCHEMA_PATH):
        sys.exit(
            "未找到 %s —— 它是官方 SARIF 2.1.0 schema 的副本，必须随仓库一起存在。\n"
            "取法：curl -sL https://json.schemastore.org/sarif-2.1.0.json "
            "-o scripts/sarif-2.1.0-schema.json" % SCHEMA_PATH)
    return json.load(io.open(SCHEMA_PATH, encoding="utf-8"))


def check(schema, validator, doc, label):
    错误 = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    if not 错误:
        return 0
    print("✗ %s：%d 个 schema 错误" % (label, len(错误)), file=sys.stderr)
    for e in 错误[:20]:
        print("    /%s" % "/".join(str(p) for p in e.path), file=sys.stderr)
        print("      %s" % e.message[:240], file=sys.stderr)
    if len(错误) > 20:
        print("    …还有 %d 个" % (len(错误) - 20), file=sys.stderr)
    return 1


def selftest(schema, validator):
    """**先证明这把尺子量得到东西**——拿一份已知不合规的样例，看它报不报。

    这条自检不是形式：这个仓库里已经有过好几次"检查一直在跑、其实什么都没量到"
    （保真证书、依赖修复版、SARIF 定位断言各一次）。一个只会说"通过"的校验器
    比没有校验器更坏。
    """
    doc = json.loads(json.dumps(MINIMAL_SAMPLE))
    if check(schema, validator, doc, "样例（应当通过）"):
        print("样例本身就不合规——schema 或样例取错了", file=sys.stderr)
        return 1

    坏的 = json.loads(json.dumps(MINIMAL_SAMPLE))
    # ① 把 logicalLocations 挪回 result 上（正是修复前那处错位）
    res = 坏的["runs"][0]["results"][0]
    res["logicalLocations"] = res["locations"][0].pop("logicalLocations")
    if not check(schema, validator, 坏的, "logicalLocations 挂错位置（应当报错）"):
        print("!!! 尺子是空的：把 logicalLocations 挪到 result 上，校验器没反应", file=sys.stderr)
        return 1

    坏的2 = json.loads(json.dumps(MINIMAL_SAMPLE))
    # ② tags 写成裸字符串（修复前那处）
    坏的2["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"] = "security"
    if not check(schema, validator, 坏的2, "tags 写成字符串（应当报错）"):
        print("!!! 尺子是空的：tags 写成裸字符串，校验器没反应", file=sys.stderr)
        return 1

    print("✓ 自检通过：干净样例 0 错误，两处已知错位都被报出来")
    return 0


def main(argv):
    try:
        import jsonschema
    except ImportError:
        print("需要 jsonschema：pip install jsonschema", file=sys.stderr)
        return 2

    schema = load_schema()
    validator = jsonschema.Draft7Validator(schema)

    if not argv or argv == ["--selftest"]:
        return selftest(schema, validator)

    失败 = 0
    for path in argv:
        try:
            doc = json.load(io.open(path, encoding="utf-8"))
        except Exception as error:
            print("读不了 %s：%s" % (path, error), file=sys.stderr)
            失败 = 1
            continue
        n = sum(len(r.get("results", [])) for r in doc.get("runs", []))
        失败 |= check(schema, validator, doc, "%s（%d 条结果）" % (path, n))
        if not 失败:
            print("✓ %s：%d 条结果，0 个 schema 错误" % (path, n))
    return 失败


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
