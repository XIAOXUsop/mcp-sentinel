package io.github.xiaoxusop.mcpsentinel;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * 不可信输入的消毒。
 *
 * <p><b>为什么安全扫描器自己也需要这个</b>：被扫描的服务器是**不可信方**，
 * 而它的 {@code serverInfo.name}、工具名、描述都会原样进入本工具的报告与 SARIF。
 * 实测过两种后果：
 * <ul>
 *   <li>服务器名里带换行 → 在报告里**伪造出**"工具面指纹"、"风险 HIGH=0"这类行，
 *       还能注入 GitHub Actions 的 {@code ::notice::} 工作流命令；</li>
 *   <li>同一个换行进到 SARIF 的 {@code artifactLocation.uri} → 生成非法 URI，
 *       官方 schema 校验失败，GitHub Code Scanning **整体拒收**这份报告。</li>
 * </ul>
 * 一个安全工具被它扫描的对象反向注入，是最不该发生的事。
 *
 * <p><b>只用在输出边界</b>，绝不在摄入处消毒：指纹必须基于**原始**名字，
 * 否则两个不同的原始名可能被消成同一个，反而制造出检测盲区。
 */
public final class Sanitizer {

    /** 报告里单个字段的默认长度上限 */
    public static final int DEFAULT_LIMIT = 200;

    /**
     * MCP 规范对工具名的要求：1–128 个字符，取自 {@code [A-Za-z0-9_.-]}。
     *
     * <p>服务器名规范没有这么严格，但同理——不合规的名字本身就该被报出来。
     */
    private static final Pattern VALID_NAME = Pattern.compile("^[A-Za-z0-9_.-]{1,128}$");

    /** URI 片段里保留原样的字符；其余一律百分号编码 */
    private static final Pattern URI_SAFE = Pattern.compile("[A-Za-z0-9._-]");

    private Sanitizer() {
    }

    /**
     * 供人读的报告：控制字符转成**可见**转义。
     *
     * <p>ANSI 转义显示成字样 {@code ESC}（Trail of Bits 在运行时代理侧的做法）——
     * 终端控制序列不该在安全报告里被解释执行。
     */
    public static String forReport(String text) {
        return forReport(text, DEFAULT_LIMIT);
    }

    public static String forReport(String text, int limit) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            if (sb.length() >= limit) {
                sb.append('…');
                break;
            }
            char c = text.charAt(i);
            if (isInvisible(c)) {
                if (c == 0x1B) {
                    sb.append("ESC");
                } else if (c == '\n') {
                    sb.append("\\n");
                } else if (c == '\r') {
                    sb.append("\\r");
                } else if (c == '\t') {
                    sb.append("\\t");
                } else {
                    sb.append("\\u%04x".formatted((int) c));
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * 需要转义或剔除的字符：C0/C1 控制符、ANSI 转义、行分隔符、
     * 双向控制符（U+202A–202E）、零宽字符。
     *
     * <p>后两类正是 {@code INVISIBLE_CHARACTERS} 要抓的东西——在报告里把它们显示成
     * {@code ​} 这样的可见转义，比让它们继续隐形更有用。
     */
    private static boolean isInvisible(char c) {
        return c < 0x20
                || (c >= 0x7F && c <= 0x9F)
                || c == 0x2028 || c == 0x2029
                || (c >= 0x202A && c <= 0x202E)
                || (c >= 0x2066 && c <= 0x2069)
                || (c >= 0x200B && c <= 0x200F)
                || c == 0xFEFF;
    }

    /** 供 SARIF 文本字段使用：与报告同一套转义，只是限长更宽 */
    public static String forSarifText(String text) {
        return forReport(text, 1000);
    }

    /**
     * 供 URI 片段使用：只保留 {@code [A-Za-z0-9._-]}，其余百分号编码。
     *
     * <p>换行、空格、反斜杠都是 URI 里的非法字符；直接放进去会让整份 SARIF
     * 过不了校验而被拒收。
     */
    public static String forUriSegment(String text) {
        if (text == null || text.isEmpty()) {
            return "unnamed";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : text.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            int value = b & 0xFF;
            char c = (char) value;
            if (value < 0x80 && URI_SAFE.matcher(String.valueOf(c)).matches()) {
                sb.append(c);
            } else {
                sb.append('%').append("%02X".formatted(value));
            }
        }
        return sb.toString();
    }

    /** 名字是否符合规范字符集——不合规本身就是一条发现 */
    public static boolean isValidName(String name) {
        return name != null && VALID_NAME.matcher(name).matches();
    }

    /** 说明名字为什么不合规，供告警文案使用 */
    public static String whyInvalid(String name) {
        if (name == null || name.isEmpty()) {
            return "为空";
        }
        if (name.length() > 128) {
            return "长度 %d 超过规范上限 128".formatted(name.length());
        }
        StringBuilder bad = new StringBuilder();
        name.codePoints().forEach(cp -> {
            String c = new String(Character.toChars(cp));
            if (!c.matches("[A-Za-z0-9_.-]") && bad.length() < 40) {
                bad.append("\\u%04x".formatted(cp));
            }
        });
        return "含规范外的字符 " + (bad.isEmpty() ? "（含控制字符或不可见字符）"
                : bad.toString().toLowerCase(Locale.ROOT));
    }
}
