package io.github.xiaoxusop.mcpsentinel.cli;
import java.nio.file.*;
import java.util.*;

/** Starts two independent real CLI approvals from one external barrier. */
public class ApprovalBarrierLauncher {
    public static void main(String[] args) throws Exception {
        Path ready=Path.of(args[0]), gate=Path.of(args[1]); Files.writeString(ready,"ready");
        long deadline=System.nanoTime()+20_000_000_000L;
        while (!Files.exists(gate)) {
            if (System.nanoTime()>deadline) throw new IllegalStateException("barrier timed out");
            Thread.sleep(5);
        }
        System.exit(Main.run(Arrays.copyOfRange(args,2,args.length),System.out,System.err));
    }
}
