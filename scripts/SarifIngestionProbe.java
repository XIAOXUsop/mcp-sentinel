import io.github.xiaoxusop.mcpsentinel.*;
import java.nio.file.*;
import java.util.*;

/** One synthetic INFO-only title change for controlled SARIF ingestion. */
public class SarifIngestionProbe {
    public static void main(String[] args) throws Exception {
        Path out=Path.of(args[0]); Files.createDirectories(out);
        var json=JsonSupport.reader();
        var schema=json.readTree("{\"type\":\"object\",\"properties\":{\"value\":{\"type\":\"boolean\"}},\"additionalProperties\":false}");
        var hints=json.readTree("{\"readOnlyHint\":true,\"destructiveHint\":false,\"idempotentHint\":true,\"openWorldHint\":false}");
        var a=new ToolDefinition("read_value","Review A","Reads the selected configuration value.",schema,schema,hints);
        var b=new ToolDefinition("read_value","Review B",a.description(),schema,schema,hints);
        var before=ToolSurface.of("sarif-ingestion-probe",List.of(a));
        var after=ToolSurface.of("sarif-ingestion-probe",List.of(b));
        Baseline.of(before,"sarif-ingestion-probe",List.of()).write(out.resolve("baseline.json"));
        SurfaceSnapshot.of(after,false,"sarif-ingestion-probe").write(out.resolve("changed.json"));
    }
}
