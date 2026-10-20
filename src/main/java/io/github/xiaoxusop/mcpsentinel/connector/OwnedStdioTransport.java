package io.github.xiaoxusop.mcpsentinel.connector;

import io.github.xiaoxusop.mcpsentinel.*;
import io.modelcontextprotocol.spec.*;
import io.modelcontextprotocol.json.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.*;

/** Bounded UTF-8 byte lines; owns and cleans up only the process tree it starts. */
final class OwnedStdioTransport implements McpClientTransport {
    private final ServerTarget target;
    private final McpJsonMapper mapper;
    private final AtomicLong bytes = new AtomicLong();
    private final Set<ProcessHandle> descendants = ConcurrentHashMap.newKeySet();
    private volatile Consumer<Throwable> errors = ignored -> { };
    private volatile boolean closing;
    private volatile Process process;
    private final Object writeLock = new Object();
    private final List<Thread> workers = new ArrayList<>();
    OwnedStdioTransport(ServerTarget target, McpJsonMapper mapper) { this.target = target; this.mapper = mapper; }
    public void setExceptionHandler(Consumer<Throwable> handler) { errors = handler; }
    public synchronized Mono<Void> connect(Function<Mono<McpSchema.JSONRPCMessage>, Mono<McpSchema.JSONRPCMessage>> handler) {
        return Mono.fromCallable(() -> {
            synchronized (this) {
                if (closing || process != null) throw new IOException("stdio 连接已关闭或已启动");
                List<String> command = new ArrayList<>(); command.add(target.command()); command.addAll(target.args());
                ProcessBuilder builder = new ProcessBuilder(command); builder.environment().putAll(target.resolveEnvironment(System::getenv));
                process = builder.start();
                workers.add(Thread.ofVirtual().name("sentinel-stdout").start(() -> read(handler)));
                workers.add(Thread.ofVirtual().name("sentinel-stderr").start(this::drainError));
                workers.add(Thread.ofVirtual().name("sentinel-process-watch").start(() -> {
                    try { while (!closing) { process.descendants().forEach(descendants::add); Thread.sleep(20); } }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                }));
            }
            return true;
        }).then();
    }
    private void read(Function<Mono<McpSchema.JSONRPCMessage>, Mono<McpSchema.JSONRPCMessage>> handler) {
        try (InputStream input = new BufferedInputStream(process.getInputStream())) {
            while (!closing) {
                ByteArrayOutputStream line = new ByteArrayOutputStream(); int value;
                while ((value = input.read()) != -1) {
                    if (bytes.incrementAndGet() > BoundedInput.SESSION_BYTES) throw new IOException("stdio 累计响应超过 32 MiB");
                    if (value == '\n') break;
                    if (line.size() >= BoundedInput.MESSAGE_BYTES) throw new IOException("stdio 原始响应超过 16 MiB");
                    line.write(value);
                }
                if (value == -1 && line.size() == 0) break;
                if (line.size() == 0) continue;
                var message = McpSchema.deserializeJsonRpcMessage(mapper, BoundedInput.decode(line.toByteArray()));
                handler.apply(Mono.just(message)).block();
            }
            if (!closing) errors.accept(new IOException("stdio 服务在采集完成前关闭"));
        } catch (Exception e) { if (!closing) errors.accept(e); }
    }
    private void drainError() {
        try (InputStream input = process.getErrorStream()) {
            byte[] buffer = new byte[4096]; long total = 0; int count;
            while (!closing && (count = input.read(buffer)) != -1) {
                total += count;
                if (total > BoundedInput.MESSAGE_BYTES) { errors.accept(new IOException("stdio stderr 超过 16 MiB")); break; }
            }
        } catch (IOException e) { if (!closing) errors.accept(e); }
    }
    public Mono<Void> sendMessage(McpSchema.JSONRPCMessage message) {
        return Mono.fromCallable(() -> {
            synchronized (writeLock) {
                if (closing || process == null) throw new IOException("stdio 连接不可用");
                process.getOutputStream().write(mapper.writeValueAsBytes(message)); process.getOutputStream().write('\n'); process.getOutputStream().flush();
            }
            return true;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
    public <T> T unmarshalFrom(Object value, TypeRef<T> type) { return mapper.convertValue(value, type); }
    public Mono<Void> closeGracefully() { return Mono.fromRunnable(this::closeOwned); }
    private synchronized void closeOwned() {
        if (closing) return;
        closing = true;
        if (process == null) return;
        process.descendants().forEach(descendants::add);
        List<ProcessHandle> owned = new ArrayList<>(descendants);
        owned.sort(Comparator.comparingInt(OwnedStdioTransport::depth).reversed());
        owned.add(process.toHandle());
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        for (ProcessHandle handle : owned) {
            if (!handle.isAlive()) continue;
            // Reap children while their parent is still alive (important on Linux).
            handle.destroy();
            try { handle.onExit().get(Math.min(TimeUnit.MILLISECONDS.toNanos(50), Math.max(1,deadline-System.nanoTime())),TimeUnit.NANOSECONDS); }
            catch (Exception e) {
                handle.destroyForcibly();
                try { handle.onExit().get(Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS); }
                catch (Exception forceError) { if (forceError instanceof InterruptedException) Thread.currentThread().interrupt(); }
            }
        }
        for (Thread worker : workers) worker.interrupt();
        try { process.getOutputStream().close(); process.getInputStream().close(); process.getErrorStream().close(); } catch (IOException ignored) { }
        if (owned.stream().anyMatch(ProcessHandle::isAlive)) throw new IllegalStateException("本次 stdio 进程树清理未完成");
    }
    private static int depth(ProcessHandle handle) {
        int depth = 0;
        while (depth < 64) {
            var parent = handle.parent();
            if (parent.isEmpty()) break;
            handle = parent.get(); depth++;
        }
        return depth;
    }
}
