package io.github.xiaoxusop.mcpsentinel;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.nio.file.*;

/** Limits allocation before parsing, including files that grow while being read. */
public final class BoundedInput {
    public static final int MESSAGE_BYTES = 16 * 1024 * 1024;
    public static final int SESSION_BYTES = 32 * 1024 * 1024;
    public static final int FILE_BYTES = 32 * 1024 * 1024;
    private BoundedInput() { }
    public static String read(Path file) throws IOException {
        if (Files.size(file) > FILE_BYTES) throw new IOException("输入文件超过安全上限 32 MiB");
        try (InputStream input = Files.newInputStream(file)) {
            byte[] bytes = input.readNBytes(FILE_BYTES + 1);
            if (bytes.length > FILE_BYTES) throw new IOException("输入文件超过安全上限 32 MiB");
            return decode(bytes);
        }
    }
    public static String decode(byte[] bytes) throws IOException {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }
}
