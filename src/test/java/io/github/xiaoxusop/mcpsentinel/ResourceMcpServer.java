package io.github.xiaoxusop.mcpsentinel;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Controlled long-line, array, stderr and process-tree fixtures. */
public class ResourceMcpServer {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("child")) { Thread.sleep(60_000); return; }
        var json = JsonSupport.reader();
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null) {
                var request = json.readTree(line); if (!request.has("id")) continue;
                var response = json.createObjectNode().put("jsonrpc", "2.0"); response.set("id", request.get("id"));
                if (request.path("method").asText().equals("initialize")) {
                    var result = response.putObject("result"); result.set("protocolVersion", request.path("params").path("protocolVersion"));
                    result.putObject("capabilities").putObject("tools"); result.putObject("serverInfo").put("name","resources").put("version","1");
                    System.out.println(response); System.out.flush(); continue;
                }
                if (args[0].equals("blocked-write")) {
                    Files.writeString(Path.of(args[1]),Long.toString(ProcessHandle.current().pid()));
                    var result=response.putObject("result"); result.putArray("tools");
                    result.put("nextCursor","x".repeat(1024*1024));
                    System.out.println(response); System.out.flush();
                    Thread.sleep(60_000); // Never read the next request; its large cursor fills the pipe.
                } else if (args[0].equals("hang")) {
                    String java = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
                    var child = new ProcessBuilder(java,"-cp",System.getProperty("java.class.path"),ResourceMcpServer.class.getName(),"child").start();
                    Files.writeString(Path.of(args[1]), ProcessHandle.current().pid()+"\n"+child.pid());
                    Thread.sleep(60_000);
                } else {
                    OutputStream stream = args[0].equals("stderr") ? System.err : System.out;
                    byte[] chunk = new byte[8192]; Arrays.fill(chunk,(byte)' ');
                    for (int i=0;i<BoundedInput.MESSAGE_BYTES/8192+2;i++) stream.write(chunk);
                    stream.flush(); Thread.sleep(60_000);
                }
            }
        }
    }
}
