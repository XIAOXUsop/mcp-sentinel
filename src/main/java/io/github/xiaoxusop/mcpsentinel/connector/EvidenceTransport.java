package io.github.xiaoxusop.mcpsentinel.connector;

import io.github.xiaoxusop.mcpsentinel.*;
import io.modelcontextprotocol.spec.*;
import io.modelcontextprotocol.json.TypeRef;
import reactor.core.publisher.Mono;
import java.util.*;
import java.util.function.*;

/** Extracts evidence before SDK Tool/ToolAnnotations deserialization can discard or coerce it. */
final class EvidenceTransport implements McpClientTransport {
    record Page(List<ToolDefinition> tools, String cursor) { }
    private final McpClientTransport delegate;
    private final com.fasterxml.jackson.databind.ObjectMapper json = JsonSupport.reader();
    private final Map<McpSchema.ListToolsResult, Page> pages = new IdentityHashMap<>();
    EvidenceTransport(McpClientTransport delegate) { this.delegate = delegate; }
    public Mono<Void> connect(Function<Mono<McpSchema.JSONRPCMessage>, Mono<McpSchema.JSONRPCMessage>> handler) { return delegate.connect(handler); }
    public void setExceptionHandler(Consumer<Throwable> handler) { delegate.setExceptionHandler(handler); }
    public Mono<Void> sendMessage(McpSchema.JSONRPCMessage message) { return delegate.sendMessage(message); }
    public Mono<Void> closeGracefully() { return delegate.closeGracefully(); }
    public List<String> protocolVersions() { return delegate.protocolVersions(); }
    public synchronized <T> T unmarshalFrom(Object data, TypeRef<T> type) {
        if (type.getType().equals(McpSchema.ListToolsResult.class)) {
            var raw = json.valueToTree(data);
            if (!raw.isObject() || !raw.path("tools").isArray()) throw new IllegalArgumentException("工具列表缺少 tools 数组");
            String cursor = null;
            if (raw.has("nextCursor")) {
                if (!raw.get("nextCursor").isTextual()) throw new IllegalArgumentException("nextCursor 必须为字符串");
                cursor = raw.get("nextCursor").textValue();
            }
            List<ToolDefinition> tools = new ArrayList<>();
            for (var node : raw.path("tools")) {
                for (String key : List.of("title", "description"))
                    if (node.has(key) && !node.get(key).isTextual()) throw new IllegalArgumentException("工具 " + key + " 必须为字符串");
                for (String key : List.of("annotations", "outputSchema"))
                    if (node.has(key) && !node.get(key).isObject()) throw new IllegalArgumentException("工具 " + key + " 必须为对象");
                tools.add(ToolDefinition.fromJson(node));
            }
            // The client only needs the cursor; evidence never travels through SDK Tool POJOs.
            var response = new McpSchema.ListToolsResult(List.of(), cursor);
            if (pages.size() >= 16) throw new IllegalStateException("同时待消费的工具列表证据超过上限");
            pages.put(response, new Page(List.copyOf(tools), cursor));
            @SuppressWarnings("unchecked") T result = (T) response;
            return result;
        }
        return delegate.unmarshalFrom(data, type);
    }
    synchronized Page takePage(McpSchema.ListToolsResult response) {
        Page page = pages.remove(response);
        if (page == null) throw new IllegalStateException("工具列表缺少匹配该响应的原始采集证据");
        return page;
    }
}
