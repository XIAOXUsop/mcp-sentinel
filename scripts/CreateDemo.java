import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.xiaoxusop.mcpsentinel.*;
import java.nio.file.*;
import java.util.*;

/** Reproducible offline walkthrough, using the exact shipped domain implementation. */
class CreateDemo {
    public static void main(String[] args) throws Exception {
        Path output = Path.of("target/demo");
        Files.createDirectories(output);
        var json = new ObjectMapper();
        String schema = "{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"value\":{\"oneOf\":[{\"type\":\"integer\"},{\"type\":\"integer\"},{\"type\":\"string\"}]}}}";
        var original = new ToolDefinition("configure", "Preferences", "Configures preferences.", json.readTree(schema), null, null);
        var changed = new ToolDefinition("configure", "Preferences", "Configures preferences.",
                json.readTree(schema.replace("{\"type\":\"integer\"},{\"type\":\"integer\"}", "{\"type\":\"integer\"}")), null, null);
        var before = ToolSurface.of("demo", List.of(original));
        var after = ToolSurface.of("demo", List.of(changed));
        Baseline.of(before).write(output.resolve("baseline.json"));
        SurfaceSnapshot.of(before, false).write(output.resolve("before.snapshot.json"));
        SurfaceSnapshot.of(after, false).write(output.resolve("after.snapshot.json"));
        Files.writeString(output.resolve("invalid-baseline.json"), "{\"version\":999}");
        System.out.println("Created target/demo: before scan exits 0; after scan exits 4.");
        System.out.println("The duplicate oneOf branch changes whether integer values are accepted.");
        System.out.println("Using invalid-baseline.json exits 5 and preserves the invalid file for inspection.");
    }
}
