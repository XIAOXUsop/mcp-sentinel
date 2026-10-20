import io.github.xiaoxusop.mcpsentinel.*;
import java.nio.file.*;

/** Test-only synchronization at checked-write and completed-replace boundaries. */
public class AtomicWriteProbe {
    public static void main(String[] args) throws Exception {
        Path target=Path.of(args[1]), candidate=Path.of(args[2]), marker=Path.of(args[3]);
        if (args[0].equals("before")) {
            AtomicFiles.write(target,Files.readString(candidate),temp->{
                Baseline.read(temp); Files.writeString(marker,"checked temporary file"); pause();
            });
        } else {
            var old=Baseline.read(target); Baseline.read(candidate).writeExpected(target,old);
            Files.writeString(marker,"atomic replacement completed"); pause();
        }
    }
    private static void pause() {
        try { Thread.sleep(30000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
