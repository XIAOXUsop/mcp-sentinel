package io.github.xiaoxusop.mcpsentinel.cli;

import java.nio.file.*;
import java.util.*;

/** Validation adapter; invokes the tested JAR's CLI, then reads Linux's own VmHWM. */
public class MeasureLauncher {
    public static void main(String[] args) throws Exception {
        long start=System.nanoTime();
        int code=Main.run(Arrays.copyOfRange(args,1,args.length),System.out,System.err);
        long elapsed=System.nanoTime()-start;
        Path status=Path.of("/proc/self/status");
        String hwm="";
        if (Files.exists(status)) {
            for (String line:Files.readAllLines(status)) if (line.startsWith("VmHWM:"))
                hwm=line.replaceAll("[^0-9]", "");
        }
        Files.writeString(Path.of(args[0]), "{\"cliBodyNanos\":"+elapsed+",\"linuxVmHwmKiB\":"+(hwm.isEmpty()?"null":hwm)+"}");
        System.exit(code);
    }
}
