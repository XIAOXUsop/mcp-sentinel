import io.github.xiaoxusop.mcpsentinel.*;
import io.github.xiaoxusop.mcpsentinel.connector.*;
import java.nio.file.*;

/** Reads negotiated metadata from the exact production collection path. */
public class CollectionMetadata {
    public static void main(String[] args) throws Exception {
        var target=ServerTarget.read(Path.of(args[0]));
        var result=McpConnector.connect(target);
        if (!result.ok()) throw new IllegalStateException(result.error());
        var evidence=JsonSupport.reader().createObjectNode();
        evidence.put("protocolVersion",result.protocolVersion());
        evidence.put("server",result.serverName()); evidence.put("targetId",target.identity());
        evidence.put("surfaceFingerprint",result.surface().fingerprint());
        Files.writeString(Path.of(args[1]),evidence.toPrettyString());
    }
}
