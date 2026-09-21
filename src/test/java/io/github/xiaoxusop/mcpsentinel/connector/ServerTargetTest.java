package io.github.xiaoxusop.mcpsentinel.connector;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配置里 `transport` 字段的解析。
 *
 * <p>为什么这件事值得单独一个测试类：**配置写错时，报出来的必须是一个配置错误，
 * 而不是一个网络错误。** 这个仓库为同一件事栽过两次（见 README 的 bug #15）——
 * 一次是拼错的子命令真的去拉起了子进程，另一次就是下面这条。
 */
class ServerTargetTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Path config(Path dir, String json) throws IOException {
        Path file = dir.resolve("mcp.json");
        Files.writeString(file, json);
        return file;
    }

    @Test
    void stdioIsTheDefaultWhenTransportIsAbsent() throws IOException {
        assertEquals(ServerTarget.Transport.STDIO, ServerTarget.Transport.parse(null));
        assertEquals(ServerTarget.Transport.STDIO, ServerTarget.Transport.parse(""));
        assertEquals(ServerTarget.Transport.STDIO, ServerTarget.Transport.parse("  "));
        assertEquals(ServerTarget.Transport.STDIO, ServerTarget.Transport.parse("stdio"));
    }

    @Test
    void streamableHttpHasAShortAlias() throws IOException {
        assertEquals(ServerTarget.Transport.STREAMABLE_HTTP,
                ServerTarget.Transport.parse("streamable-http"));
        // 下划线与大小写都归一化
        assertEquals(ServerTarget.Transport.STREAMABLE_HTTP,
                ServerTarget.Transport.parse("Streamable_HTTP"));
        assertEquals(ServerTarget.Transport.STREAMABLE_HTTP, ServerTarget.Transport.parse("http"));
    }

    /**
     * **`sse` 必须被拒收，而不是被当成 streamable-http 收下。**
     *
     * <p>它们不是一套协议：MCP 早期用的 HTTP+SSE（GET 建事件流、再 POST 到它给的端点）
     * 后来被 Streamable HTTP 取代，握手方式不同。把 `sse` 当后者用，结果是按
     * Streamable HTTP 去请求一个 SSE-only 的服务器、握手失败，报出来是
     * 「连接服务器失败」（退出 2）——**把人引到网络排查上去**，而真正的问题在配置里。
     *
     * <p>实测（2026-09-22）：改之前，`"transport": "sse"` 得到退出码 **2** 与
     * 「连接服务器失败：… 目标: http://…」；同一份配置把 transport 换成 `websocket`
     * 反而得到退出码 **1** 与「不支持的 transport」。**写错的越像真的，报得越离谱。**
     */
    @Test
    void sseIsRejectedInsteadOfBeingSilentlyTreatedAsStreamableHttp() {
        IOException error = assertThrows(IOException.class,
                () -> ServerTarget.Transport.parse("sse"),
                "sse 是另一种传输，不能静默当成 streamable-http");

        // 报错要能让人直接照着改：指明它是什么、本工具支持什么、该怎么办
        String message = error.getMessage();
        assertTrue(message.contains("sse"), message);
        assertTrue(message.contains("streamable-http"), "要告诉使用者该写什么：" + message);
        assertFalse(message.contains("不支持") && message.contains("只支持 stdio 与 streamable-http"),
                "不能落到那条笼统的 default 分支上——那条会把 sse 和真正的乱码混为一谈：" + message);
    }

    @Test
    void unknownTransportsAreRejectedWithAConfigError() {
        for (String value : new String[] {"websocket", "grpc", "tcp", "nonsense"}) {
            IOException error = assertThrows(IOException.class,
                    () -> ServerTarget.Transport.parse(value));
            assertTrue(error.getMessage().contains(value), error.getMessage());
        }
    }

    /** 从配置文件读进来时也要走同一套判定——解析逻辑不能有第二个入口。 */
    @Test
    void readingAConfigWithSseFailsAtConfigTimeNotAtConnectTime(@TempDir Path dir) throws IOException {
        Path file = config(dir, MAPPER.writeValueAsString(Map.of(
                "server", "sse-srv",
                "transport", "sse",
                "url", "http://127.0.0.1:1/mcp")));

        IOException error = assertThrows(IOException.class, () -> ServerTarget.read(file));
        assertTrue(error.getMessage().contains("sse"), error.getMessage());
    }

    @Test
    void readingAConfigWithStdioStillWorks(@TempDir Path dir) throws IOException {
        Path file = config(dir, MAPPER.writeValueAsString(Map.of(
                "server", "local",
                "command", "java")));

        ServerTarget target = ServerTarget.read(file);
        assertEquals(ServerTarget.Transport.STDIO, target.transport());
    }
}
