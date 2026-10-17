package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.xiaoxusop.mcpsentinel.connector.ServerTarget;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ValidationAndCoverageTest {
    private static final com.fasterxml.jackson.databind.ObjectMapper JSON = JsonSupport.reader();

    private static ToolDefinition tool(String schema, String annotations) throws Exception {
        return new ToolDefinition("configure", "Preferences", "Configures preferences.", JSON.readTree(schema), null, JSON.readTree(annotations));
    }

    @Test void annotationFieldsRejectCoercionAtConstructionAndAfterMutation() throws Exception {
        for (String key : List.of("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")) {
            for (String value : List.of("\"true\"", "\"unexpected\"", "0", "null", "[]", "{}")) {
                assertThrows(IllegalArgumentException.class, () -> tool("{}", "{\"" + key + "\":" + value + "}"));
            }
        }
        ToolDefinition mutable = tool("{}", "{\"readOnlyHint\":true}");
        ((ObjectNode) mutable.annotations()).put("readOnlyHint", "false");
        assertThrows(IllegalArgumentException.class, () -> ToolFingerprint.of(mutable));
    }

    @Test void knownKeywordValidationIsIndependentOfReferences() throws Exception {
        for (String invalid : List.of(
                "{\"dependentRequired\":{\"a/b~c\":[\"aux\",\"aux\"]}}",
                "{\"dependentRequired\":{\"v\":[1]}}", "{\"dependentRequired\":[]}",
                "{\"required\":[\"v\",\"v\"]}", "{\"type\":[]}", "{\"type\":\"unsupported\"}",
                "{\"properties\":{\"v\":{\"required\":[1]}}}", "{\"oneOf\":[]}",
                "{\"additionalProperties\":null}", "{\"minLength\":-1}", "{\"multipleOf\":0}")) {
            for (boolean reference : List.of(false, true)) {
                ObjectNode schema = (ObjectNode) JSON.readTree(invalid);
                if (reference) schema.put("$ref", "#/$defs/unused");
                assertThrows(IllegalArgumentException.class, () -> SchemaCanonicalizer.canonicalize(schema), schema.toString());
                assertThrows(IllegalArgumentException.class, () -> new ToolDefinition("t", "D", schema));
            }
        }
    }

    @Test void instancesAndUnknownExtensionsAreNotValidatedAsSchemas() throws Exception {
        for (String keyword : List.of("const", "default", "x-extension")) {
            ToolDefinition definition = tool("{\"" + keyword + "\":{\"required\":[\"x\",\"x\"],\"type\":\"business\",\"dependentRequired\":{\"v\":[1]}}}", "{}");
            assertDoesNotThrow(() -> ToolFingerprint.of(definition));
        }
        assertDoesNotThrow(() -> tool("{\"enum\":[[1,2],[1,2]],\"dependentRequired\":{\"v\":[]},\"maxLength\":100.0}", "{}"));
    }

    @Test void independentCoverageRejectsUnclaimedPathsBesideInfo() throws Exception {
        JsonNode before = JSON.readTree("{\"annotations\":{\"readOnlyHint\":true,\"destructiveHint\":true}}");
        JsonNode after = JSON.readTree("{\"annotations\":{\"readOnlyHint\":false,\"destructiveHint\":\"unexpected\"}}");
        var paths = PathChange.between("configure", 0, before, after);
        Change info = new Change("ANNOTATION_READONLY_FLIPPED", "configure", 0, ChangeSeverity.INFO, "known", "x")
                .at("/annotations/readOnlyHint");
        var graded = SchemaDiff.completeCoverage("configure", 0, paths, List.of(info));
        assertTrue(graded.stream().anyMatch(c -> c.severity() == ChangeSeverity.DANGEROUS
                && c.paths().contains("/annotations/destructiveHint")));
    }

    @Test void coverageUsesPointerBoundariesAndPreservesEveryPath() throws Exception {
        var paths = PathChange.between("configure", 0, JSON.readTree("{\"x\":0,\"x-other\":0,\"a/b~c\":0}"),
                JSON.readTree("{\"x\":1,\"x-other\":1,\"a/b~c\":1}"));
        Change known = new Change("KNOWN", "configure", 0, ChangeSeverity.INFO, "known", "x").at("/x");
        var graded = SchemaDiff.completeCoverage("configure", 0, paths, List.of(known));
        var residual = graded.stream().filter(c -> c.id().equals("UNGRADED_SCHEMA_CHANGE")).findFirst().orElseThrow();
        assertTrue(residual.paths().containsAll(List.of("/x-other", "/a~1b~0c")));
        assertFalse(residual.paths().contains("/x"));
        assertEquals(paths.size(), graded.stream().flatMap(c -> c.paths().stream()).distinct().count());
    }

    @Test void knownDefaultsRemainInfoWhileUnknownAnnotationsBlock() throws Exception {
        var before = tool("{}", "{\"readOnlyHint\":true}");
        var equivalent = tool("{}", "{\"readOnlyHint\":true,\"destructiveHint\":true}");
        var first = Baseline.of(ToolSurface.of("s", List.of(before))).diffAgainst(ToolSurface.of("s", List.of(equivalent)));
        assertTrue(first.blocking(ChangeSeverity.BREAKING).isEmpty());
        assertTrue(first.changes().stream().anyMatch(c -> c.paths().contains("/annotations/destructiveHint")));
        var next = tool("{}", "{\"readOnlyHint\":false,\"x-policy\":{\"a/b~c\":\"unknown\"}}");
        var second = Baseline.of(ToolSurface.of("s", List.of(before))).diffAgainst(ToolSurface.of("s", List.of(next)));
        assertFalse(second.blocking(ChangeSeverity.DANGEROUS).isEmpty());
        assertEquals(second.paths().size(), second.changes().stream().flatMap(c -> c.paths().stream()).distinct().count());
    }

    @Test void diagnosticsRemoveCredentialsAndArgumentsBeforeDisplayEscaping() {
        ServerTarget stdio = new ServerTarget("stdio", ServerTarget.Transport.STDIO, "test", List.of("argument-private-value"),
                Map.of("TOKEN", "environment-private-value"), "", Map.of(), java.time.Duration.ofSeconds(1));
        ServerTarget http = new ServerTarget("http", ServerTarget.Transport.STREAMABLE_HTTP, "", List.of(), Map.of(),
                "https://example.test/private?token=query-private-value", Map.of("Authorization", "Bearer header-private-value"), java.time.Duration.ofSeconds(1));
        String message = "failed argument-private-value environment-private-value Bearer header-private-value https://example.test/private?token=query-private-value\n::warning::x";
        String safe = http.redactDiagnostic(stdio.redactDiagnostic(message));
        assertFalse(safe.contains("private-value"));
        ScanError error = new ScanError("CONNECTION_FAILED", "INITIALIZE", safe);
        assertFalse(error.message().contains("\n"));
        assertTrue(error.message().contains("\\n"));
    }
}
