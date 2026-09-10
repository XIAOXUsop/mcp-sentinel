package io.github.xiaoxusop.mcpsentinel;

import java.text.Normalizer;
import java.util.HashMap;
import java.util.Map;

/**
 * 匹配前的文本归一化。
 *
 * <p>存在的理由是一次实测绕过：{@code "Ignore аll previous instructions"} 里那个
 * {@code а} 是西里尔字母 U+0430，不是拉丁 {@code a}——肉眼完全一样，正则一条都不命中。
 * 这不是理论构造：arXiv 2607.02357 报告同形字与零宽字符拆分绕过了被调查的
 * 9 个扫描器中的 90% 以上。
 *
 * <p>三步：NFKC 折叠兼容字符（全角等）→ 去掉零宽与双向控制符 → 常见同形字折回拉丁。
 *
 * <p><b>只用于"找指令性措辞"这一件事</b>，不要用它做指纹或不可见字符检测——
 * 那些地方恰恰需要看到原始字符（第 2 步会把它们抹掉）。
 */
public final class TextNormalizer {

    /** 零宽与双向控制符：它们的作用就是让人看不见夹带了什么 */
    private static final String INVISIBLE = "[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]";

    /**
     * 同形字折叠表：视觉上与拉丁字母几乎无差别的西里尔/希腊字母。
     *
     * <p>刻意只收常见的这批，不做全量 confusables（那需要 Unicode 的 confusables.txt，
     * 是一份几千行的数据）。**覆盖不完备**——README 里如实标注：
     * 罕见字符的同形替换仍然能绕过。
     */
    private static final Map<Integer, Integer> CONFUSABLES = new HashMap<>();

    private static void fold(String from, String to) {
        for (int i = 0; i < from.length(); i++) {
            CONFUSABLES.put((int) from.charAt(i), (int) to.charAt(i));
        }
    }

    static {
        // 西里尔小写
        fold("аеорсухѕіјԁһӏмтнвкгп", "aeopcyxsijdhlmthbkrn");
        // 西里尔大写
        fold("АВЕКМНОРСТУХЅІЈ", "ABEKMHOPCTYXSIJ");
        // 希腊小写
        fold("αεικορντυχ", "aeikopntvx");
        // 希腊大写
        fold("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEZHIKMNOPTYX");
    }

    private TextNormalizer() {
    }

    /** NFKC + 去零宽 + 同形字折叠 */
    public static String fold(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        String normalized = Normalizer.normalize(text, Normalizer.Form.NFKC)
                .replaceAll(INVISIBLE, "");
        StringBuilder sb = new StringBuilder(normalized.length());
        normalized.codePoints().forEach(cp -> {
            Integer folded = CONFUSABLES.get(cp);
            sb.appendCodePoint(folded == null ? cp : folded);
        });
        return sb.toString();
    }
}
