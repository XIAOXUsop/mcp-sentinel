package io.github.xiaoxusop.mcpsentinel.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.xiaoxusop.mcpsentinel.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(90)
class OfflineWorkflowTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private record Result(int code, String out, String err) { }
    private static Result invoke(String... args) {
        var out = new ByteArrayOutputStream(); var err = new ByteArrayOutputStream();
        int code = Main.run(args, new PrintStream(out, true, StandardCharsets.UTF_8), new PrintStream(err, true, StandardCharsets.UTF_8));
        return new Result(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }
    private static ToolSurface surface(String title, String schema) throws Exception {
        return ToolSurface.of("offline-test", List.of(new ToolDefinition("configure", title, "Configures preferences.",
                JSON.readTree(schema), null, null)));
    }

    @Test void originalThreeBypassesNowFailAtTheCliBoundary(@TempDir Path dir) throws Exception {
        String[] before = {
                "{\"properties\":{\"value\":{\"oneOf\":[{\"type\":\"integer\"},{\"type\":\"integer\"},{\"type\":\"string\"}]}}}",
                "{\"properties\":{\"value\":{\"enum\":[[1,2]]}}}",
                "{\"properties\":{\"options\":{\"properties\":{}}}}"
        };
        String[] after = {
                "{\"properties\":{\"value\":{\"oneOf\":[{\"type\":\"integer\"},{\"type\":\"string\"}]}}}",
                "{\"properties\":{\"value\":{\"enum\":[[2,1]]}}}",
                "{\"properties\":{\"options\":{\"properties\":{\"extra\":{\"type\":\"string\"}}}}}"
        };
        for (int i = 0; i < before.length; i++) {
            Path baseline = dir.resolve("baseline-" + i + ".json");
            Path snapshot = dir.resolve("snapshot-" + i + ".json");
            Path report = dir.resolve("report-" + i + ".json");
            Baseline.of(surface("Old", before[i])).write(baseline);
            SurfaceSnapshot.of(surface(i == 2 ? "New" : "Old", after[i]), false).write(snapshot);
            Result result = invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(), "--json", report.toString());
            assertEquals(4, result.code, result.out + result.err);
            var node = JSON.readTree(Files.readString(report));
            assertEquals("FAIL", node.path("status").asText());
            assertEquals("COMPLETE", node.path("collectionStatus").asText());
            assertFalse(node.path("baselineFingerprint").asText().isBlank());
        }
    }

    @Test void approvalUsesReviewedFingerprintsAndRejectsStaleSurface(@TempDir Path dir) throws Exception {
        var old = surface("Old", "{\"additionalProperties\":false}");
        var next = surface("Next", "{\"additionalProperties\":false}");
        Path baseline = dir.resolve("base.json"), snapshot = dir.resolve("snapshot.json");
        Baseline.of(old).write(baseline); SurfaceSnapshot.of(next, false).write(snapshot);
        byte[] original = Files.readAllBytes(baseline);
        assertEquals(1, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(), "--accept-changes").code);
        SurfaceSnapshot.of(surface("Changed again", "{\"additionalProperties\":false}"), false).write(snapshot);
        assertEquals(5, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(), "--accept-changes",
                "--expect-baseline", old.fingerprint(), "--expect-surface", next.fingerprint()).code);
        assertArrayEquals(original, Files.readAllBytes(baseline));
        SurfaceSnapshot.of(next, false).write(snapshot);
        assertEquals(0, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(), "--accept-changes",
                "--expect-baseline", old.fingerprint(), "--expect-surface", next.fingerprint()).code);
        assertEquals(next.fingerprint(), Baseline.read(baseline).surfaceFingerprint());
        assertEquals(old.fingerprint(), Baseline.read(baseline).acceptedChanges().getFirst().beforeFingerprint());
    }

    @Test void targetMismatchAndRedactedSnapshotsCannotSupplyApprovalEvidence(@TempDir Path dir) throws Exception {
        var current = surface("T", "{}");
        Path baseline = dir.resolve("base.json"), snapshot = dir.resolve("snapshot.json");
        Baseline.of(current, "target:one", List.of()).write(baseline);
        SurfaceSnapshot.of(current, false, "target:two").write(snapshot);
        assertEquals(5, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString()).code);
        SurfaceSnapshot.of(current, true, "target:one").write(snapshot);
        assertEquals(5, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString()).code);
        assertEquals(0, invoke("scan", "--snapshot", snapshot.toString(), "--risk-only").code);
        ObjectNode node = (ObjectNode) JSON.readTree(Files.readString(snapshot));
        node.put("redacted", "false"); Files.writeString(snapshot, node.toString());
        assertEquals(1, invoke("scan", "--snapshot", snapshot.toString(), "--risk-only").code);
    }

    @Test void failedScansAndOutputFailuresHaveAccurateJson(@TempDir Path dir) throws Exception {
        Path report = dir.resolve("report.json"), sarif = dir.resolve("report.sarif");
        Result missing = invoke("scan", "--config", dir.resolve("missing.json").toString(), "--json", report.toString(), "--sarif", sarif.toString());
        assertEquals(1, missing.code);
        assertEquals("FAILED", JSON.readTree(Files.readString(report)).path("collectionStatus").asText());
        assertFalse(JSON.readTree(Files.readString(sarif)).path("runs").get(0).path("invocations").get(0).path("executionSuccessful").asBoolean());
        Path snapshot = dir.resolve("snapshot.json");
        SurfaceSnapshot.of(surface("T", "{\"additionalProperties\":false}"), false).write(snapshot);
        Path directory = Files.createDirectory(dir.resolve("cannot-replace"));
        Files.writeString(directory.resolve("keep.txt"), "keep");
        Result failedOutput = invoke("scan", "--snapshot", snapshot.toString(), "--risk-only", "--out", directory.toString(), "--json", report.toString());
        assertEquals(6, failedOutput.code, failedOutput.err);
        var node = JSON.readTree(Files.readString(report));
        assertEquals(6, node.path("exitCode").asInt());
        assertEquals("FAIL", node.path("status").asText());
        assertEquals("OUTPUT_WRITE_FAILED", node.path("errorCategory").asText());
        assertEquals("REPORT_WRITE", node.path("errors").get(0).path("phase").asText());
        assertEquals("keep", Files.readString(directory.resolve("keep.txt")));
    }

    @Test void reportsCannotOverwriteTheirInputs(@TempDir Path dir) throws Exception {
        Path snapshot = dir.resolve("snapshot.json");
        SurfaceSnapshot.of(surface("T", "{}"), false).write(snapshot);
        byte[] original = Files.readAllBytes(snapshot);
        assertEquals(1, invoke("scan", "--snapshot", snapshot.toString(), "--risk-only", "--json", snapshot.toString()).code);
        assertArrayEquals(original, Files.readAllBytes(snapshot));
    }

    @Test void importingDoesNotStartTheConfiguredCommandAndKeepsEnvReferences(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("client.json"), normalized = dir.resolve("normalized.json");
        Files.writeString(config, """
                {"mcpServers":{"safe":{"command":"not-an-executable-mcp-sentinel-test","env":{"TOKEN":"${MCP_TOKEN}"}}}}
                """);
        assertEquals(0, invoke("import-config", "--config", config.toString(), "--out", normalized.toString()).code);
        assertEquals("${MCP_TOKEN}", JSON.readTree(Files.readString(normalized)).path("env").path("TOKEN").asText());
        assertEquals(1, invoke("import-config", "--config", config.toString(), "--all-targets").code);
        assertEquals(1, invoke("snapshot", "--config", config.toString(), "--out", normalized.toString(), "--all-targets").code);
    }

    @Test void lockCannotOverwriteItsConfigAndMissingEnvIsAConfigFailure(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json");
        Files.writeString(config, "{\"server\":\"test\",\"command\":\"not-an-executable\"}");
        byte[] before = Files.readAllBytes(config);
        assertEquals(1, invoke("lock", "--config", config.toString(), "--baseline", config.toString()).code);
        assertArrayEquals(before, Files.readAllBytes(config));
        Files.writeString(config, "{\"server\":\"test\",\"command\":\"not-an-executable\",\"env\":{\"TOKEN\":\"${MCP_SENTINEL_MISSING_TEST_VARIABLE_64193}\"}}");
        var result = invoke("scan", "--config", config.toString(), "--risk-only");
        assertEquals(1, result.code, result.err);
        assertTrue(result.err.contains("环境变量"));
    }

    private static ObjectNode target(Path spec, int timeout) {
        ObjectNode target = JSON.createObjectNode();
        target.put("command", System.getProperty("java.home") + File.separator + "bin" + File.separator + "java");
        target.put("requestTimeoutSeconds", timeout);
        target.putArray("args").add("-cp").add(System.getProperty("java.class.path"))
                .add(RawMcpServer.class.getName()).add(spec.toString());
        return target;
    }

    @Test void batchReportsEveryTargetAndDoesNotHideAFailedConnection(@TempDir Path dir) throws Exception {
        Path spec = dir.resolve("server.json"), config = dir.resolve("client.json");
        Files.writeString(spec, """
                {"serverName":"same-remote-name","tools":[{"name":"ping","description":"Lists status.","inputSchema":{"type":"object","additionalProperties":false}}]}
                """);
        ObjectNode root = JSON.createObjectNode(), servers = root.putObject("mcpServers");
        servers.set("good", target(spec, 5));
        servers.putObject("bad").put("transport", "streamable-http").put("url", "http://127.0.0.1:1/mcp").put("requestTimeoutSeconds", 1);
        Files.writeString(config, root.toString());
        Path report = dir.resolve("batch.json"), sarif = dir.resolve("batch.sarif");
        Result result = invoke("scan", "--config", config.toString(), "--all-targets", "--risk-only", "--json", report.toString(), "--sarif", sarif.toString());
        assertEquals(2, result.code, result.err);
        var node = JSON.readTree(Files.readString(report));
        assertEquals(2, node.path("targets").size());
        assertEquals("PARTIAL", node.path("collectionStatus").asText());
        assertEquals("FAIL", node.path("status").asText());
        assertEquals(ScanReport.REPORT_VERSION, node.path("reportVersion").asInt());
        assertEquals(1, node.path("errors").size());
        for (var entry : node.path("targets")) {
            if (entry.path("exitCode").asInt() == 0) {
                assertEquals(0, entry.path("errors").size());
                assertTrue(entry.path("tools").get(0).path("fingerprint").asText().matches("[0-9a-f]{64}"));
            } else {
                assertFalse(entry.path("errors").get(0).path("phase").asText().isBlank());
                assertFalse(entry.path("errors").get(0).path("message").asText().isBlank());
            }
        }
        var runs = JSON.readTree(Files.readString(sarif)).path("runs");
        assertEquals(2, runs.size());
        assertNotEquals(runs.get(0).path("automationDetails").path("id"), runs.get(1).path("automationDetails").path("id"));
    }

    @Test void batchShapeIsStableForOneTargetAndBaselineNamesDoNotCollide(@TempDir Path dir) throws Exception {
        Path spec = dir.resolve("server.json"), config = dir.resolve("client.json"), report = dir.resolve("batch.json");
        Files.writeString(spec, "{\"serverName\":\"same-name\",\"tools\":[]}");
        ObjectNode root = JSON.createObjectNode(), servers = root.putObject("mcpServers");
        servers.set("Files", target(spec, 5));
        Files.writeString(config, root.toString());
        assertEquals(0, invoke("scan", "--config", config.toString(), "--all-targets", "--risk-only", "--json", report.toString()).code);
        assertEquals("MULTI_TARGET", JSON.readTree(Files.readString(report)).path("mode").asText());
        assertEquals(1, JSON.readTree(Files.readString(report)).path("targets").size());
        servers.set("files", target(spec, 5)); Files.writeString(config, root.toString());
        Path baselines = dir.resolve("baselines");
        assertEquals(0, invoke("lock", "--config", config.toString(), "--all-targets", "--baseline-dir", baselines.toString()).code);
        try (var paths = Files.list(baselines)) {
            var names = paths.map(p -> p.getFileName().toString()).filter(n -> n.endsWith(".lock.json"))
                    .map(n -> n.toLowerCase(java.util.Locale.ROOT)).distinct().toList();
            assertEquals(2, names.size());
        }
        assertEquals(0, invoke("scan", "--config", config.toString(), "--all-targets", "--baseline-dir", baselines.toString(), "--json", report.toString()).code);
        assertEquals(2, JSON.readTree(Files.readString(report)).path("targets").size());
    }

    @Test void selfConsistentLegacyAnnotationBypassIsRejectedBeforeApproval(@TempDir Path dir) throws Exception {
        Path baseline = dir.resolve("base.json"), snapshot = dir.resolve("snapshot.json"), report = dir.resolve("report.json");
        var schema = JSON.readTree("{\"type\":\"object\",\"additionalProperties\":false}");
        var original = new ToolDefinition("configure", "Old", "Configures preferences.", schema, null,
                JSON.readTree("{\"readOnlyHint\":true,\"destructiveHint\":true}"));
        Baseline.of(ToolSurface.of("s", List.of(original))).write(baseline);
        byte[] oldBaseline = Files.readAllBytes(baseline);
        for (String title : List.of("Old", "New")) {
            var valid = new ToolDefinition("configure", title, original.description(), schema, null,
                    JSON.readTree("{\"readOnlyHint\":false,\"destructiveHint\":true}"));
            SurfaceSnapshot.of(ToolSurface.of("s", List.of(valid)), false).write(snapshot);
            ObjectNode root = (ObjectNode) JSON.readTree(Files.readString(snapshot));
            ObjectNode raw = (ObjectNode) root.path("tools").get(0);
            ((ObjectNode) raw.path("annotations")).put("destructiveHint", "unexpected");
            // Reproduce the old serializer's self-consistent fingerprint, not just tampering detection.
            ObjectNode legacyCanonical = valid.toJson();
            legacyCanonical.set("annotations", SchemaCanonicalizer.canonicalizeMetadata(raw.path("annotations")));
            String legacyFingerprint = ToolFingerprint.sha256(legacyCanonical.toString());
            raw.put("fingerprint", legacyFingerprint);
            root.put("surfaceFingerprint", ToolFingerprint.sha256("configure=" + legacyFingerprint + "\n"));
            Files.writeString(snapshot, root.toString());
            var result = invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(),
                    "--accept-changes", "--expect-baseline", Baseline.read(baseline).surfaceFingerprint(),
                    "--expect-surface", root.path("surfaceFingerprint").asText(), "--json", report.toString());
            assertEquals(1, result.code, result.out + result.err);
            var failure = JSON.readTree(Files.readString(report));
            assertEquals("SNAPSHOT_READ", failure.path("errors").get(0).path("phase").asText());
            assertTrue(failure.path("errors").get(0).path("message").asText().contains("/annotations/destructiveHint"));
            assertArrayEquals(oldBaseline, Files.readAllBytes(baseline));
        }
    }

    @Test void legacyInvalidDependentRequiredCannotSupplySnapshotOrBaselineEvidence(@TempDir Path dir) throws Exception {
        var valid = surface("T", "{\"type\":\"object\",\"dependentRequired\":{\"value\":[\"aux\"]}}");
        Path baseline = dir.resolve("base.json"), snapshot = dir.resolve("snapshot.json"), report = dir.resolve("report.json");
        Baseline.of(valid).write(baseline); SurfaceSnapshot.of(valid, false).write(snapshot);
        String correctSnapshot = Files.readString(snapshot);
        ObjectNode invalidSnapshot = (ObjectNode) JSON.readTree(correctSnapshot);
        ((com.fasterxml.jackson.databind.node.ArrayNode) invalidSnapshot.path("tools").get(0).path("inputSchema").path("dependentRequired").path("value")).add("aux");
        Files.writeString(snapshot, invalidSnapshot.toString());
        assertEquals(1, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(), "--json", report.toString()).code);
        assertTrue(JSON.readTree(Files.readString(report)).path("errors").get(0).path("message").asText().contains("dependentRequired"));
        Files.writeString(snapshot, correctSnapshot);
        ObjectNode invalidBaseline = (ObjectNode) JSON.readTree(Files.readString(baseline));
        ((com.fasterxml.jackson.databind.node.ArrayNode) invalidBaseline.path("tools").get(0).path("inputSchema").path("dependentRequired").path("value")).add("aux");
        Files.writeString(baseline, invalidBaseline.toString());
        byte[] originalInvalid = Files.readAllBytes(baseline);
        assertEquals(5, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(), "--json", report.toString()).code);
        var failure = JSON.readTree(Files.readString(report));
        assertEquals("COMPLETE", failure.path("collectionStatus").asText());
        assertEquals("BASELINE_READ", failure.path("errors").get(0).path("phase").asText());
        assertTrue(failure.path("errors").get(0).path("message").asText().contains("dependentRequired"));
        assertArrayEquals(originalInvalid, Files.readAllBytes(baseline));
    }

    @Test void reportFingerprintsPreserveDuplicateOccurrencesAndHideRedactedEvidence(@TempDir Path dir) throws Exception {
        Path snapshot = dir.resolve("snapshot.json"), report = dir.resolve("report.json");
        var a = new ToolDefinition("same", "Reads status.", JSON.readTree("{\"additionalProperties\":false}"));
        var b = new ToolDefinition("same", "Reads other status.", a.inputSchema());
        var current = ToolSurface.of("s", List.of(a, b));
        SurfaceSnapshot.of(current, false).write(snapshot);
        assertEquals(3, invoke("scan", "--snapshot", snapshot.toString(), "--risk-only", "--json", report.toString()).code);
        var tools = JSON.readTree(Files.readString(report)).path("tools");
        assertEquals(2, tools.size());
        assertEquals(0, tools.get(0).path("occurrence").asInt()); assertEquals(1, tools.get(1).path("occurrence").asInt());
        assertEquals(ToolFingerprint.of(a), tools.get(0).path("fingerprint").asText());
        assertEquals(ToolFingerprint.of(b), tools.get(1).path("fingerprint").asText());
        SurfaceSnapshot.of(current, true).write(snapshot);
        assertEquals(3, invoke("scan", "--snapshot", snapshot.toString(), "--risk-only", "--json", report.toString()).code);
        var redacted = JSON.readTree(Files.readString(report));
        assertFalse(redacted.path("fingerprintsAvailable").asBoolean());
        assertTrue(redacted.path("surfaceFingerprint").asText().isEmpty());
        for (var tool : redacted.path("tools")) assertTrue(tool.path("fingerprint").asText().isEmpty());
    }

    @Test void collectedTargetMismatchRetainsEvidenceAndSpecificFailure(@TempDir Path dir) throws Exception {
        var current = surface("T", "{\"additionalProperties\":false}");
        Path baseline = dir.resolve("base.json"), snapshot = dir.resolve("snapshot.json"), report = dir.resolve("report.json");
        Baseline.of(current, "target:one", List.of()).write(baseline);
        SurfaceSnapshot.of(current, false, "target:two").write(snapshot);
        assertEquals(5, invoke("scan", "--snapshot", snapshot.toString(), "--baseline", baseline.toString(), "--json", report.toString()).code);
        var failure = JSON.readTree(Files.readString(report));
        assertEquals("COMPLETE", failure.path("collectionStatus").asText());
        assertEquals("BASELINE_TARGET", failure.path("errors").get(0).path("phase").asText());
        assertEquals(current.fingerprint(), failure.path("surfaceFingerprint").asText());
        assertEquals(ToolFingerprint.of(current.tools().getFirst()), failure.path("tools").get(0).path("fingerprint").asText());
    }

    @Test void failedProcessHasPerTargetDetailsWithoutConfiguredSecrets(@TempDir Path dir) throws Exception {
        Path config = dir.resolve("mcp.json"), report = dir.resolve("report.json");
        Files.writeString(config, "{\"server\":\"broken-process\",\"command\":\"mcp-sentinel-missing-audit-executable\",\"args\":[\"argument-private-value\"],\"env\":{\"TOKEN\":\"environment-private-value\"},\"timeoutSeconds\":1}");
        assertEquals(2, invoke("scan", "--config", config.toString(), "--risk-only", "--json", report.toString()).code);
        String text = Files.readString(report); var failure = JSON.readTree(text);
        assertEquals("broken-process", failure.path("server").asText());
        assertEquals("FAILED", failure.path("collectionStatus").asText());
        assertEquals("INITIALIZE", failure.path("errors").get(0).path("phase").asText());
        assertTrue(failure.path("errors").get(0).path("message").asText().length() > 10);
        assertFalse(text.contains("argument-private-value")); assertFalse(text.contains("environment-private-value"));
    }

    @Test void onlineCollectionRejectsMalformedKnownKeywordsBeforeLocking(@TempDir Path dir) throws Exception {
        Path spec = dir.resolve("server.json"), config = dir.resolve("mcp.json"), baseline = dir.resolve("base.json"), report = dir.resolve("report.json");
        for (String schema : List.of("{\"type\":\"object\",\"dependentRequired\":{\"v\":[\"aux\",\"aux\"]}}",
                "{\"type\":\"object\",\"$ref\":\"#/$defs/unused\",\"required\":[\"v\",\"v\"]}")) {
            ObjectNode root = JSON.createObjectNode(); root.put("serverName", "invalid-schema");
            root.putArray("tools").addObject().put("name", "configure").put("description", "Configures preferences.")
                    .set("inputSchema", JSON.readTree(schema));
            Files.writeString(spec, root.toString()); Files.writeString(config, target(spec, 5).toString());
            var scan = invoke("scan", "--config", config.toString(), "--risk-only", "--json", report.toString());
            assertEquals(2, scan.code, scan.out + scan.err);
            assertTrue(JSON.readTree(Files.readString(report)).path("errors").get(0).path("message").asText().contains("无效 Schema"));
            assertEquals(2, invoke("lock", "--config", config.toString(), "--out", baseline.toString()).code);
            assertFalse(Files.exists(baseline));
        }
    }
}
