package io.github.xiaoxusop.mcpsentinel.connector;
import io.github.xiaoxusop.mcpsentinel.*;
import io.modelcontextprotocol.json.*;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

/** Counts JSON message bytes before SDK parsing on every transport. */
final class BudgetJsonMapper implements McpJsonMapper {
    private final McpJsonMapper delegate = new JacksonMcpJsonMapper(JsonSupport.reader());
    private final AtomicLong total = new AtomicLong();
    private void charge(int size) throws IOException {
        if (size > BoundedInput.MESSAGE_BYTES) throw new IOException("原始 JSON 消息超过 16 MiB");
        if (total.addAndGet(size) > BoundedInput.SESSION_BYTES) throw new IOException("累计 JSON 消息超过 32 MiB");
    }
    private void charge(String value) throws IOException {
        if (value.length() > BoundedInput.MESSAGE_BYTES) throw new IOException("原始 JSON 消息超过 16 MiB");
        charge(value.getBytes(StandardCharsets.UTF_8).length);
    }
    public <T> T readValue(String value, Class<T> type) throws IOException { charge(value); return delegate.readValue(value, type); }
    public <T> T readValue(byte[] value, Class<T> type) throws IOException { charge(value.length); return delegate.readValue(value, type); }
    public <T> T readValue(String value, TypeRef<T> type) throws IOException { charge(value); return delegate.readValue(value, type); }
    public <T> T readValue(byte[] value, TypeRef<T> type) throws IOException { charge(value.length); return delegate.readValue(value, type); }
    public <T> T convertValue(Object value, Class<T> type) { return delegate.convertValue(value, type); }
    public <T> T convertValue(Object value, TypeRef<T> type) { return delegate.convertValue(value, type); }
    public String writeValueAsString(Object value) throws IOException { return delegate.writeValueAsString(value); }
    public byte[] writeValueAsBytes(Object value) throws IOException { return delegate.writeValueAsBytes(value); }
}
