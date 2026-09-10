package io.github.xiaoxusop.mcpsentinel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * 工具指纹。
 *
 * <p>存在的理由很直接：MCP 的工具定义是**运行时从服务器拉取**的，而模型会照着这份定义决定
 * 调什么工具、传什么参数。如果服务器在某次启动后改了描述或放宽了 schema，
 * 调用方是**看不到**的——这就是 OWASP 所说的 tool poisoning / rug pull：
 * 先发布一个人畜无害的定义取得信任，之后再悄悄改成有权限的那版。
 *
 * <p>指纹把"这份定义当时长什么样"固定下来，使任何变化都变成可检测的事件。
 */
public final class ToolFingerprint {

    private static final int SHORT_LENGTH = 16;

    private ToolFingerprint() {
    }

    /** 单个工具的完整指纹（SHA-256，64 位十六进制） */
    public static String of(ToolDefinition tool) {
        return sha256(tool.canonicalForm());
    }

    /**
     * 整个工具面的指纹。
     *
     * <p>按工具名排序后拼接再求哈希——因此工具顺序变化不会改变工具面指纹，
     * 但任何一个工具的新增、删除或内容变化都会改变它。
     */
    public static String ofSurface(List<ToolDefinition> tools) {
        StringBuilder sb = new StringBuilder();
        tools.stream()
                .sorted(java.util.Comparator.comparing(ToolDefinition::name))
                .forEach(tool -> sb.append(tool.name()).append('=').append(of(tool)).append('\n'));
        return sha256(sb.toString());
    }

    /** 短指纹，用于人读的报告与 git 提交信息 */
    public static String shortOf(String fullFingerprint) {
        return fullFingerprint.length() <= SHORT_LENGTH
                ? fullFingerprint : fullFingerprint.substring(0, SHORT_LENGTH);
    }

    static String sha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("本机不支持 SHA-256", e);
        }
    }
}
