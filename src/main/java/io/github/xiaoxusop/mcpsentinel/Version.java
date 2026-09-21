package io.github.xiaoxusop.mcpsentinel;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * 本产物的版本号，**唯一**的一份。
 *
 * ── 为什么要有这个类 ──────────────────────────────────────────────
 *
 * 版本号原先在两处手写死，而且两处都落后于 pom：
 *
 * <pre>
 *   SarifWriter.java    driver.version = "0.2.0"   （pom 是 0.5.3）
 *   McpConnector.java   clientInfo     = "0.5.1"
 * </pre>
 *
 * 一个 0.5.3 的产物因此对外自称是 0.2.0 / 0.5.1：SARIF 里那份会进 code scanning
 * 的告警记录，MCP 那份会在握手时发给对端。两次升版都漏了——因为它们既不进门禁，
 * 也不进任何断言。
 *
 * **手写死的版本号必然会漂**，所以这里不靠"记得同步"，而是让它只有一个来源：
 * pom 的 `<version>` 经资源过滤写进 `mcp-sentinel-version.properties`，
 * 代码只从这里读。
 *
 * ── 读不到时不要静默给个像样的值 ──────────────────────────────────
 *
 * 读不到就如实返回 {@code "unknown"}。给个 `"0.0.0"` 之类的默认值会让"打包漏了
 * 资源文件"表现成一个看起来正常的版本号——这个仓库反复栽在"看起来没问题"上。
 */
public final class Version {

    private static final String RESOURCE = "mcp-sentinel-version.properties";

    /** 读不到资源时用这个值；它是**看得出来的**异常，不是一个像样的版本号。 */
    public static final String UNKNOWN = "unknown";

    private static final String VALUE = load();

    private Version() {
    }

    /** 本产物的版本号；资源缺失时返回 {@link #UNKNOWN}。 */
    public static String value() {
        return VALUE;
    }

    private static String load() {
        try (InputStream in = Version.class.getClassLoader().getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return UNKNOWN;
            }
            Properties properties = new Properties();
            properties.load(in);
            String version = properties.getProperty("version");
            if (version == null || version.isBlank() || version.contains("${")) {
                // `${` 说明资源过滤没生效（拿到的还是占位符本身）——
                // 那是构建配置坏了，别把它当成版本号发出去。
                return UNKNOWN;
            }
            return version.trim();
        } catch (IOException | RuntimeException e) {
            return UNKNOWN;
        }
    }
}
