package io.github.xiaoxusop.mcpsentinel.connector;
import io.github.xiaoxusop.mcpsentinel.*;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(90)
class ResourceIngressTest {
    private ServerTarget stdio(String mode, Path file) {
        return new ServerTarget("resources",System.getProperty("java.home")+File.separator+"bin"+File.separator+"java",
            List.of("-cp",System.getProperty("java.class.path"),ResourceMcpServer.class.getName(),mode,file.toString()))
            .withConnectTimeout(Duration.ofSeconds(2)).withRequestTimeout(Duration.ofSeconds(1));
    }
    @Test void oversizedLinesAndStderrFailWithinBudget(@TempDir Path dir) {
        for (String mode : List.of("line","stderr")) {
            long start = System.nanoTime();
            var result = McpConnector.connect(stdio(mode,dir.resolve("unused")));
            assertFalse(result.ok()); assertTrue(Duration.ofNanos(System.nanoTime()-start).toSeconds()<8, result.error());
        }
    }
    @Test void timeoutLeavesNeitherTheServerNorItsChildAlive(@TempDir Path dir) throws Exception {
        Path pids = dir.resolve("pids");
        assertFalse(McpConnector.connect(stdio("hang",pids)).ok());
        assertTrue(Files.exists(pids),"fixture did not reach tools/list");
        for (String value : Files.readAllLines(pids)) assertFalse(ProcessHandle.of(Long.parseLong(value)).map(ProcessHandle::isAlive).orElse(false),value);
    }
    @Test void serverThatStopsReadingCannotBlockTheRequestWriterOrCleanup(@TempDir Path dir) throws Exception {
        Path pids=dir.resolve("writer-pid"); long start=System.nanoTime();
        var result=McpConnector.connect(stdio("blocked-write",pids).withRequestTimeout(Duration.ofSeconds(2)));
        assertFalse(result.ok()); assertTrue(Duration.ofNanos(System.nanoTime()-start).toSeconds()<10);
        assertTrue(Files.exists(pids));
        long pid=Long.parseLong(Files.readString(pids));
        assertFalse(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false));
    }
    @Test void oversizedFilesAreRejectedBeforeParsing(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("large.json");
        try (var channel = Files.newByteChannel(file,StandardOpenOption.CREATE,StandardOpenOption.WRITE)) {
            channel.position(BoundedInput.FILE_BYTES); channel.write(ByteBuffer.wrap(new byte[]{1}));
        }
        assertThrows(IOException.class,()->Baseline.read(file)); assertThrows(IOException.class,()->SurfaceSnapshot.read(file));
        assertThrows(IOException.class,()->ServerTarget.read(file));
    }
    @Test void hugeArraysAndAggregateMessagesHaveLimits() throws Exception {
        String wide = "["+"0,".repeat(1_000_000)+"0]";
        assertThrows(IOException.class,()->JsonSupport.reader().readTree(wide));
        var mapper = new BudgetJsonMapper(); String message = " ".repeat(BoundedInput.MESSAGE_BYTES-2)+"{}";
        mapper.readValue(message,Map.class); mapper.readValue(message,Map.class);
        assertThrows(IOException.class,()->mapper.readValue("{}",Map.class));
    }
    @Test void chunkedAndFixedOversizedHttpResponsesAreRejected() throws Exception {
        for (boolean chunked : List.of(false,true)) {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            server.createContext("/mcp",ex->{
                ex.getRequestBody().readAllBytes(); ex.getResponseHeaders().set("Content-Type","application/json");
                ex.sendResponseHeaders(200,chunked?0:BoundedInput.MESSAGE_BYTES+8192);
                try(var output=ex.getResponseBody()) {
                    byte[] chunk = new byte[8192]; Arrays.fill(chunk,(byte)' ');
                    for(int i=0;i<BoundedInput.MESSAGE_BYTES/8192+1;i++) output.write(chunk);
                } catch(IOException ignored) { }
            }); server.start();
            try {
                var target = new ServerTarget("http",ServerTarget.Transport.STREAMABLE_HTTP,"",List.of(),Map.of(),
                    "http://127.0.0.1:"+server.getAddress().getPort()+"/mcp",Map.of(),Duration.ofSeconds(2));
                assertFalse(McpConnector.connect(target).ok());
            } finally { server.stop(0); }
        }
    }
    @Test void sseResponsePreservesEvidenceAndClosesItsStream() throws Exception {
        var json = JsonSupport.reader(); var disconnected = new CountDownLatch(1);
        var executor = Executors.newCachedThreadPool();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0); server.setExecutor(executor);
        server.createContext("/mcp",ex->{
            if (!ex.getRequestMethod().equals("POST")) { ex.sendResponseHeaders(202,-1); ex.close(); return; }
            var request = json.readTree(ex.getRequestBody());
            if (!request.has("id")) { ex.sendResponseHeaders(202,-1); ex.close(); return; }
            var response = json.createObjectNode().put("jsonrpc","2.0"); response.set("id",request.get("id"));
            if(request.path("method").asText().equals("initialize")) {
                var result=response.putObject("result"); result.set("protocolVersion",request.path("params").path("protocolVersion"));
                result.putObject("capabilities").putObject("tools"); result.putObject("serverInfo").put("name","sse").put("version","1");
                byte[] bytes=response.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Type","application/json"); ex.sendResponseHeaders(200,bytes.length);
                try(var output=ex.getResponseBody()) { output.write(bytes); } return;
            }
            response.set("result",json.readTree("{\"tools\":[{\"name\":\"status\",\"inputSchema\":{},\"annotations\":{\"x-policy\":\"retained\"}}]}"));
            ex.getResponseHeaders().set("Content-Type","text/event-stream"); ex.sendResponseHeaders(200,0);
            try(var output=ex.getResponseBody()) {
                output.write(("data: "+response+"\n\n").getBytes(java.nio.charset.StandardCharsets.UTF_8)); output.flush();
                for(int i=0;i<3000;i++) { output.write(": heartbeat\n\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)); output.flush(); Thread.sleep(20); }
            } catch(Exception ignored) { } finally { disconnected.countDown(); }
        }); server.start();
        try {
            var target = new ServerTarget("sse",ServerTarget.Transport.STREAMABLE_HTTP,"",List.of(),Map.of(),
                "http://127.0.0.1:"+server.getAddress().getPort()+"/mcp",Map.of(),Duration.ofSeconds(3));
            var result=McpConnector.connect(target); assertTrue(result.ok(),result.error());
            assertEquals("retained",result.surface().tools().getFirst().annotations().path("x-policy").asText());
            assertTrue(disconnected.await(3,TimeUnit.SECONDS),"HTTP SSE body remained open after return");
        } finally { server.stop(0); executor.shutdownNow(); }
    }
}
