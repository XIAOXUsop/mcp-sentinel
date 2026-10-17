package io.github.xiaoxusop.mcpsentinel;

/** A stable machine-readable failure; callers redact configuration secrets before construction. */
public record ScanError(String category, String phase, String message) {
    public ScanError {
        message = Sanitizer.forReport(message, 1000);
    }
}
