package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.xiaoxusop.mcpsentinel.connector.McpConnector;
import io.github.xiaoxusop.mcpsentinel.connector.ServerTarget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(30)
class PaginationLimitsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static ServerTarget target(Path spec, int maxTools) {
        return new ServerTarget("pages", ServerTarget.Transport.STDIO,
                System.getProperty("java.home") + File.separator + "bin" + File.separator + "java",
                List.of("-cp", System.getProperty("java.class.path"), RawMcpServer.class.getName(), spec.toString()),
                Map.of(), "", Map.of(), Duration.ofSeconds(5), Duration.ofSeconds(5), maxTools);
    }
    private static ObjectNode tool(String name) {
        var node = JSON.createObjectNode().put("name", name).put("description", "Lists status.");
        node.putObject("inputSchema").put("type", "object").put("additionalProperties", false);
        return node;
    }
    @Test void allPagesAreCollectedAndToolBudgetAppliesAcrossPages(@TempDir Path dir) throws Exception {
        Path spec = dir.resolve("pages.json");
        var root = JSON.createObjectNode(); var pages = root.putArray("pages");
        pages.addObject().put("nextCursor", "1").putArray("tools").add(tool("first"));
        pages.addObject().putArray("tools").add(tool("second"));
        Files.writeString(spec, root.toString());
        var result = McpConnector.connect(target(spec, 2));
        assertTrue(result.ok(), result.error()); assertEquals(2, result.surface().tools().size());
        result = McpConnector.connect(target(spec, 1));
        assertFalse(result.ok()); assertTrue(result.error().contains("工具数"), result.error());
    }
    @Test void repeatedCursorFailsInsteadOfLooping(@TempDir Path dir) throws Exception {
        Path spec = dir.resolve("cycle.json");
        Files.writeString(spec, "{\"pages\":[{\"tools\":[],\"nextCursor\":\"0\"}]}");
        var result = McpConnector.connect(target(spec, 10));
        assertFalse(result.ok()); assertTrue(result.error().contains("cursor"), result.error());
    }
    @Test void pageBudgetFailsEvenWhenPagesHaveNoTools(@TempDir Path dir) throws Exception {
        Path spec = dir.resolve("many.json");
        var root = JSON.createObjectNode(); var pages = root.putArray("pages");
        for (int i = 0; i < 101; i++) pages.addObject().put("nextCursor", Integer.toString(i + 1)).putArray("tools");
        Files.writeString(spec, root.toString());
        var result = McpConnector.connect(target(spec, 1000));
        assertFalse(result.ok()); assertTrue(result.error().contains("100 页"), result.error());
    }
}
