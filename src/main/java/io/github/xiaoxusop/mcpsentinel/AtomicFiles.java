package io.github.xiaoxusop.mcpsentinel;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Checked replacement; never silently downgrade an atomic write. */
public final class AtomicFiles {
    private AtomicFiles() { }

    @FunctionalInterface
    public interface Check { void verify(Path path) throws IOException; }

    public static void write(Path file, String content, Check check) throws IOException {
        Path target = file.toAbsolutePath().normalize();
        Files.createDirectories(target.getParent());
        Path temporary = Files.createTempFile(target.getParent(), ".mcp-sentinel-", ".tmp");
        try {
            Files.writeString(temporary, content, StandardCharsets.UTF_8);
            check.verify(temporary);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                throw new IOException("文件系统不支持原子替换；原文件未改动，请改用支持原子替换的目录", e);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
