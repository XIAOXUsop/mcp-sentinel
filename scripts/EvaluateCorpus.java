import com.fasterxml.jackson.databind.node.*;
import io.github.xiaoxusop.mcpsentinel.*;
import io.github.xiaoxusop.mcpsentinel.rules.RiskRules;
import java.nio.file.*;
import java.util.*;

/** Pure comparison/heuristic measurements, separate from service and network time. */
class EvaluateCorpus {
    public static void main(String[] args) throws Exception {
        var json = JsonSupport.reader();
        var input = json.readTree(Files.readString(Path.of(args[0])));
        var result = json.createObjectNode();
        var comparisons = result.putArray("comparisons");
        for (var example : input.path("comparisons")) {
            var before = ToolDefinition.fromJson(example.path("before"));
            var after = ToolDefinition.fromJson(example.path("after"));
            var diff = Baseline.of(ToolSurface.of("evaluation", List.of(before)))
                    .diffAgainst(ToolSurface.of("evaluation", List.of(after)));
            var row = comparisons.addObject().put("id", example.path("id").asText());
            row.put("sameFingerprint", ToolFingerprint.of(before).equals(ToolFingerprint.of(after)));
            row.put("blocked", !diff.blocking(ChangeSeverity.BREAKING).isEmpty());
            row.put("structuralPaths", diff.paths().size());
        }
        var risks = result.putArray("risks");
        for (var example : input.path("risks")) {
            var tool = ToolDefinition.fromJson(example.path("tool"));
            var findings = RiskRules.evaluate(ToolSurface.of("evaluation", List.of(tool)));
            risks.addObject().put("id", example.path("id").asText())
                    .put("high", findings.stream().anyMatch(f -> f.severity() == Finding.Severity.HIGH));
        }
        var measurements = result.putArray("comparisonBenchmark");
        for (int count : List.of(100, 1000)) {
            List<ToolDefinition> original = new ArrayList<>();
            for (int i = 0; i < count; i++) original.add(new ToolDefinition("lookup_" + i, "Looks up a record.",
                    json.readTree("{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"id\":{\"type\":\"integer\"}}}")));
            var baseline = Baseline.of(ToolSurface.of("benchmark", original));
            List<ToolDefinition> changed = new ArrayList<>(original);
            changed.set(count - 1, new ToolDefinition("lookup_" + (count - 1), "Looks up a changed record.", original.getLast().inputSchema()));
            var current = ToolSurface.of("benchmark", changed);
            for (int i = 0; i < 3; i++) baseline.diffAgainst(current);
            List<Double> milliseconds = new ArrayList<>();
            long observedHeap = 0;
            for (int i = 0; i < 12; i++) {
                long start = System.nanoTime();
                if (baseline.diffAgainst(current).isClean()) throw new AssertionError("Benchmark did not compare changes");
                milliseconds.add((System.nanoTime() - start) / 1_000_000.0);
                observedHeap = Math.max(observedHeap, Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory());
            }
            Collections.sort(milliseconds);
            measurements.addObject().put("toolCount", count).put("samples", milliseconds.size())
                    .put("medianMs", milliseconds.get(6)).put("p95Ms", milliseconds.get(11))
                    .put("observedHeapBytes", observedHeap);
        }
        result.put("javaVersion", System.getProperty("java.version"));
        result.put("os", System.getProperty("os.name"));
        result.put("arch", System.getProperty("os.arch"));
        Files.writeString(Path.of(args[1]), json.writerWithDefaultPrettyPrinter().writeValueAsString(result));
    }
}
