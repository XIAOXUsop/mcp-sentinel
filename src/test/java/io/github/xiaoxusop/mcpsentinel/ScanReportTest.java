package io.github.xiaoxusop.mcpsentinel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * {@link ScanReport#highestSeverity()} 的行为。
 *
 * <p>存在的理由：这个仓库里有**两套方向相反的严重级别**——
 * {@link Finding.Severity} 声明为 {@code HIGH, MEDIUM, LOW}（ordinal 越小越严重），
 * 而 {@link ChangeSeverity} 是 {@code INFO, BREAKING, DANGEROUS}（ordinal 越大越严重）。
 * 取最高级时一个用 {@code min}、一个用 {@code max}，写反了不报错、只是安静地取错值。
 *
 * <p>这个方法是给 CI 注解报「实际分级」用的（此前报的是阈值，见 CliEndToEndTest）。
 */
class ScanReportTest {

    private static Finding finding(Finding.Severity severity) {
        return new Finding("SOME_RULE", severity, "some-tool", "消息", "");
    }

    private static ScanReport report(Finding... findings) {
        return new ScanReport("srv", "fp", findings.length, List.of(findings), null);
    }

    @Test
    void returnsHighWhenHighIsPresent() {
        assertEquals(Finding.Severity.HIGH,
                report(finding(Finding.Severity.LOW), finding(Finding.Severity.HIGH)).highestSeverity());
    }

    @Test
    void returnsMediumWhenItIsTheWorst() {
        assertEquals(Finding.Severity.MEDIUM,
                report(finding(Finding.Severity.LOW), finding(Finding.Severity.MEDIUM)).highestSeverity());
    }

    @Test
    void returnsLowWhenItIsTheOnlyOne() {
        assertEquals(Finding.Severity.LOW, report(finding(Finding.Severity.LOW)).highestSeverity());
    }

    @Test
    void returnsNullWhenThereIsNothing() {
        assertNull(report().highestSeverity());
    }
}
