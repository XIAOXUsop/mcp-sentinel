# XIAOXUsop mcp-sentinel

A Java 21 CLI for reviewing MCP tool declaration changes in CI. It captures six tool fields, computes deterministic fingerprints, explains drift, and runs local heuristic risk rules without a model service.

The current working tree is a v0.6.0 candidate. Build it with `./mvnw -B clean verify -Prelease-evidence` (`mvnw.cmd` on Windows), then run `java --class-path target/mcp-sentinel.jar scripts/CreateDemo.java`. The generated offline walkthrough lives in `target/demo`.

The October 19 review identified raw-ingress, grading and release-gate gaps. Online annotations are now checked before SDK coercion, and unknown annotation fields are retained. JSON report v3 adds explicit static-risk and drift execution states to the previous per-tool evidence. See the [report contract](report-format.md), [original findings](reviews/2026-10-19/README.md), and current [execution record](execution-status.md).

Online `lock` and `snapshot` commands launch configured stdio processes or contact HTTP services. `import-config` does not launch them. Offline `scan --snapshot` does not require a server. Keep an independently reviewed baseline in version control; ordinary CI scans must not recreate or automatically approve it.

Approval requires `--accept-changes --expect-baseline <full SHA256> --expect-surface <full SHA256>` using a report you have reviewed. Baseline format 3 and canonicalization version 2 reject older files: earlier canonicalization may have lost semantic information, so preserve old evidence and explicitly re-lock a trusted service.

Exit codes: 0 pass, 1 usage/configuration, 2 collection/connection failure, 3 static risk, 4 drift, 5 unavailable/mismatched baseline or approval, 6 output failure. JSON reports distinguish COMPLETE, PARTIAL and FAILED collection; failed scans never become a clean tool surface. Batch reports and SARIF runs retain per-target status.

Raw JSON messages are capped at 16 MiB, accumulated JSON messages at 32 MiB, and input files at 32 MiB; parsing also limits token counts and nesting. The scanner terminates its owned stdio process tree and cancels HTTP streams on closure. [Compatibility](compatibility.md) describes the scope of these limits. Stable publication requires a complete Dependabot inventory; missing permissions or an incomplete page is a failure.

The scanner does not prove implementation safety, inspect every protocol field, or intercept runtime tool results. Heuristic accuracy and real-world adoption require separate evaluation. [Chinese guide](../README.md), [integration](integration.md), [compatibility](compatibility.md), [execution record](execution-status.md).
