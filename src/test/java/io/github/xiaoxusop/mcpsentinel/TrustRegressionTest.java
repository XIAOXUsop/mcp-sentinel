package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TrustRegressionTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static ToolDefinition tool(String schema) throws Exception {
        return new ToolDefinition("configure", "Preferences", "Updates preferences.", JSON.readTree(schema), null, null);
    }
    private static ToolSurface surface(ToolDefinition tool) { return ToolSurface.of("test", List.of(tool)); }
    private static SurfaceDiff diff(ToolDefinition before, ToolDefinition after) {
        return Baseline.of(surface(before)).diffAgainst(surface(after));
    }
    private static void dangerous(ToolDefinition before, ToolDefinition after) {
        assertNotEquals(ToolFingerprint.of(before), ToolFingerprint.of(after));
        assertFalse(diff(before, after).blocking(ChangeSeverity.DANGEROUS).isEmpty());
    }

    @Test void oneOfPreservesMultiplicityButCanReorderBranches() throws Exception {
        ToolDefinition repeated = tool("{\"properties\":{\"v\":{\"oneOf\":[{\"type\":\"integer\"},{\"type\":\"integer\"},{\"type\":\"string\"}]}}}");
        ToolDefinition single = tool("{\"properties\":{\"v\":{\"oneOf\":[{\"type\":\"integer\"},{\"type\":\"string\"}]}}}");
        dangerous(repeated, single);
        ToolDefinition reordered = tool("{\"properties\":{\"v\":{\"oneOf\":[{\"type\":\"string\"},{\"type\":\"integer\"},{\"type\":\"integer\"}]}}}");
        assertEquals(ToolFingerprint.of(repeated), ToolFingerprint.of(reordered));
    }

    @Test void instanceArraysTextAndBusinessKeysRetainMeaning() throws Exception {
        for (String keyword : List.of("enum", "const", "default", "examples", "x-extension")) {
            String before = "{\"properties\":{\"v\":{\"" + keyword + "\":[[1,2],{\"description\":\" a \",\"required\":[\"z\",\"a\"]}]}}}";
            String after = before.replace("[1,2]", "[2,1]");
            for (String variant : List.of(after, before.replace(" a ", "a"))) {
                assertNotEquals(ToolFingerprint.of(tool(before)), ToolFingerprint.of(tool(variant)), keyword);
                assertFalse(diff(tool(before), tool(variant)).blocking(ChangeSeverity.BREAKING).isEmpty(), keyword);
            }
        }
    }

    @Test void propertyNamesDoNotBecomeSchemaKeywords() throws Exception {
        var definition = tool("{\"properties\":{\"enum\":{\"type\":\"string\",\"description\":\" D \"},\"required\":{\"const\":[2,1]}}}");
        var canonical = definition.toJson().path("inputSchema");
        assertEquals("D", canonical.path("properties").path("enum").path("description").asText());
        assertEquals("[2,1]", canonical.path("properties").path("required").path("const").toString());
    }

    @Test void positionalReferencesPreventArrayReordering() throws Exception {
        var before = tool("{\"$defs\":{\"choices\":{\"anyOf\":[{\"type\":\"string\"},{\"type\":\"integer\"}]}},\"$ref\":\"#/$defs/choices/anyOf/0\"}");
        var after = tool("{\"$defs\":{\"choices\":{\"anyOf\":[{\"type\":\"integer\"},{\"type\":\"string\"}]}},\"$ref\":\"#/$defs/choices/anyOf/0\"}");
        dangerous(before, after);
    }

    @Test void infoAndKnownParameterChangesCannotHideUnknownPaths() throws Exception {
        var before = tool("{\"properties\":{\"a/b~c\":{\"type\":\"object\",\"description\":\"old\",\"properties\":{}}}}");
        var after = new ToolDefinition("configure", "New title", "Updates preferences.",
                JSON.readTree("{\"properties\":{\"a/b~c\":{\"type\":\"object\",\"description\":\"new\",\"properties\":{\"extra\":{\"type\":\"string\"}}}}}"), null, null);
        var changes = diff(before, after);
        assertTrue(changes.changes().stream().anyMatch(c -> c.id().equals("TITLE_CHANGED")));
        assertTrue(changes.changes().stream().anyMatch(c -> c.id().equals("PARAM_DESCRIPTION_CHANGED")));
        assertTrue(changes.changes().stream().anyMatch(c -> c.id().equals("UNGRADED_SCHEMA_CHANGE")
                && c.detail().contains("/inputSchema/properties/a~1b~0c/properties/extra")));
        assertFalse(changes.blocking(ChangeSeverity.DANGEROUS).isEmpty());
    }

    @Test void numericTypeExpansionAndConstraintRelaxationAreDangerous() throws Exception {
        dangerous(tool("{\"properties\":{\"v\":{\"type\":\"integer\"}}}"),
                tool("{\"properties\":{\"v\":{\"type\":[\"integer\",\"number\"]}}}"));
        dangerous(tool("{\"properties\":{\"v\":{\"maxLength\":10}}}"),
                tool("{\"properties\":{\"v\":{\"maxLength\":20}}}"));
        assertEquals(ChangeSeverity.INFO, diff(tool("{\"properties\":{\"v\":{\"type\":\"number\"}}}"),
                tool("{\"properties\":{\"v\":{\"type\":[\"number\",\"integer\"]}}}")).changes().getFirst().severity());
    }

    @Test void additionalPropertiesDefaultsAndSchemaValuesAreDistinguished() throws Exception {
        assertTrue(diff(tool("{}"), tool("{\"additionalProperties\":true}")).blocking(ChangeSeverity.BREAKING).isEmpty());
        dangerous(tool("{\"additionalProperties\":false}"), tool("{}"));
        dangerous(tool("{\"additionalProperties\":{\"type\":\"integer\"}}"),
                tool("{\"additionalProperties\":{\"type\":\"string\"}}"));
        assertThrows(IllegalArgumentException.class, () -> tool("{\"additionalProperties\":null}"));
    }

    @Test void unknownAnnotationsCannotHideBehindKnownHints() throws Exception {
        var before = new ToolDefinition("configure", "", "D", JSON.readTree("{}"), null,
                JSON.readTree("{\"readOnlyHint\":true,\"x-policy\":{\"mode\":\"a\"}}"));
        var after = new ToolDefinition("configure", "", "D", JSON.readTree("{}"), null,
                JSON.readTree("{\"readOnlyHint\":false,\"x-policy\":{\"mode\":\"b\"}}"));
        assertTrue(diff(before, after).changes().stream().anyMatch(c -> c.id().equals("UNGRADED_SCHEMA_CHANGE")));
        assertFalse(diff(before, after).blocking(ChangeSeverity.DANGEROUS).isEmpty());
    }

    @Test void baselinePreservesRawEvidenceAndRejectsTampering(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("lock.json");
        ToolDefinition raw = new ToolDefinition("configure", " Title ", " D \r\n", JSON.readTree("{}"), null, null);
        Baseline baseline = Baseline.of(surface(raw));
        baseline.write(file);
        assertEquals(raw.description(), Baseline.read(file).tools().getFirst().tool().description());
        ObjectNode root = (ObjectNode) JSON.readTree(Files.readString(file));
        ((ObjectNode) root.path("tools").get(0)).put("description", "different");
        Files.writeString(file, root.toString());
        assertThrows(IOException.class, () -> Baseline.read(file));
        for (JsonNode version : List.of(JSON.getNodeFactory().numberNode(999), JSON.getNodeFactory().numberNode(4294967299L))) {
            baseline.write(file);
            root = (ObjectNode) JSON.readTree(Files.readString(file));
            root.set("version", version); Files.writeString(file, root.toString());
            assertThrows(IOException.class, () -> Baseline.read(file));
        }
        baseline.write(file);
        Files.writeString(file, Files.readString(file).replaceFirst("\\{", "{\"version\":3,"));
        assertThrows(IOException.class, () -> Baseline.read(file));
    }

    @Test void failedCheckedWriteAndStaleApprovalPreserveExistingFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("lock.json");
        var old = Baseline.of(surface(tool("{}"))); old.write(file);
        byte[] original = Files.readAllBytes(file);
        assertThrows(IOException.class, () -> AtomicFiles.write(file, "broken", p -> { throw new IOException("invalid"); }));
        assertArrayEquals(original, Files.readAllBytes(file));
        var replacement = Baseline.of(surface(tool("{\"additionalProperties\":false}"))); replacement.write(file);
        byte[] concurrent = Files.readAllBytes(file);
        assertThrows(IOException.class, () -> old.writeExpected(file, old));
        assertArrayEquals(concurrent, Files.readAllBytes(file));
        Path lock = file.resolveSibling(file.getFileName() + ".write-lock");
        try (var channel = FileChannel.open(lock, StandardOpenOption.CREATE, StandardOpenOption.WRITE); var held = channel.lock()) {
            assertThrows(IOException.class, () -> old.writeExpected(file, replacement));
        }
        assertArrayEquals(concurrent, Files.readAllBytes(file));
    }

    @Test void historicalApprovalDoesNotAuthorizeADifferentTransition() throws Exception {
        var a = surface(new ToolDefinition("configure", "A", JSON.readTree("{}")));
        var b = surface(new ToolDefinition("configure", "B", JSON.readTree("{}")));
        var c = surface(new ToolDefinition("configure", "C", JSON.readTree("{}")));
        var original = Baseline.of(a);
        Change approved = original.diffAgainst(b).changes().getFirst();
        var approval = new Baseline.AcceptedChange(approved.id(), approved.toolName(), approved.digest(),
                original.targetId(), a.fingerprint(), b.fingerprint());
        var newer = Baseline.of(c, List.of(approval));
        assertFalse(newer.diffAgainst(b).blocking(ChangeSeverity.BREAKING).isEmpty());
    }

    @Test void displayEscapesControlCharactersWithoutChangingEvidence() throws Exception {
        var change = new Change("NEW", "safe\n::warning::probe", 0, ChangeSeverity.DANGEROUS, "a\u001b[31m\rB", "x");
        assertFalse(change.format().contains("\n")); assertFalse(change.format().contains("\u001b"));
        assertTrue(change.toolName().contains("\n"));
    }

    @Test void strictParsingPreservesDecimalEvidenceAndRejectsTrailingDocuments() throws Exception {
        var reader = JsonSupport.reader();
        var first = new ToolDefinition("t", "T", reader.readTree("{\"const\":0.123456789012345678901}"));
        var second = new ToolDefinition("t", "T", reader.readTree("{\"const\":0.123456789012345678902}"));
        assertNotEquals(ToolFingerprint.of(first), ToolFingerprint.of(second));
        assertThrows(IOException.class, () -> reader.readTree("{} {}"));
        var hugeExponent = new ToolDefinition("t", "T", reader.readTree("{\"const\":1e100000}"));
        assertTrue(hugeExponent.canonicalForm().length() < 500);
    }

    @Test void structuralEvidenceContainsKnownAndUnknownPaths() throws Exception {
        var before = tool("{\"properties\":{\"v\":{\"type\":\"integer\",\"const\":1}}}");
        var after = tool("{\"properties\":{\"v\":{\"type\":\"number\",\"const\":2}}}");
        var paths = diff(before, after).paths().stream().map(PathChange::path).toList();
        assertTrue(paths.contains("/inputSchema/properties/v/type"));
        assertTrue(paths.contains("/inputSchema/properties/v/const"));
    }

    @Test void remoteDisplayNameIsNotTargetIdentity() throws Exception {
        var definition = tool("{}");
        var first = Baseline.of(ToolSurface.of("old-display-name", List.of(definition)), "stable-config-target", List.of());
        var renamed = Baseline.of(ToolSurface.of("new-display-name", List.of(definition)), "stable-config-target", List.of());
        assertTrue(first.sameContentAs(renamed));
        assertFalse(first.sameContentAs(Baseline.of(surface(definition), "other-target", List.of())));
    }
}
