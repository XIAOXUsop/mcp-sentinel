package io.github.xiaoxusop.mcpsentinel.connector;

import io.github.xiaoxusop.mcpsentinel.JsonSupport;
import io.modelcontextprotocol.spec.*;
import io.modelcontextprotocol.json.TypeRef;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import java.util.function.Function;
import static org.junit.jupiter.api.Assertions.*;

class EvidenceCorrelationTest {
    @Test void interleavedEquivalentSdkEnvelopesCannotExchangeTheirEvidence() throws Exception {
        var json=JsonSupport.reader();
        McpClientTransport unused = new McpClientTransport() {
            public Mono<Void> connect(Function<Mono<McpSchema.JSONRPCMessage>,Mono<McpSchema.JSONRPCMessage>> handler) { return Mono.empty(); }
            public Mono<Void> sendMessage(McpSchema.JSONRPCMessage message) { return Mono.empty(); }
            public Mono<Void> closeGracefully() { return Mono.empty(); }
            public <T> T unmarshalFrom(Object data,TypeRef<T> type) { throw new AssertionError("Tool evidence must precede SDK conversion"); }
        };
        var transport=new EvidenceTransport(unused); var type=new TypeRef<McpSchema.ListToolsResult>() { };
        var first=transport.unmarshalFrom(json.readTree("{\"tools\":[{\"name\":\"first\",\"inputSchema\":{}}]}"),type);
        var second=transport.unmarshalFrom(json.readTree("{\"tools\":[{\"name\":\"second\",\"inputSchema\":{}}]}"),type);
        assertEquals(first,second,"SDK envelope equality must not identify a raw response");
        assertEquals("first",transport.takePage(first).tools().getFirst().name());
        assertEquals("second",transport.takePage(second).tools().getFirst().name());
        assertThrows(IllegalStateException.class,()->transport.takePage(first));
    }
}
