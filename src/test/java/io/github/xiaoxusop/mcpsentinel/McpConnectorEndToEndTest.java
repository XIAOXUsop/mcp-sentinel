package io.github.xiaoxusop.mcpsentinel;

import io.github.xiaoxusop.mcpsentinel.connector.McpConnector;
import io.github.xiaoxusop.mcpsentinel.connector.ServerTarget;
import io.github.xiaoxusop.mcpsentinel.rules.RiskRules;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.File;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 端到端测试：**真的启动一个 MCP 服务器子进程**，通过 MCP 协议拉取工具面，
 * 再跑风险规则把投毒工具抓出来。
 *
 * <p>与纯函数测试的区别在于：这里验证的是"这个工具真的能当扫描器用"，
 * 而不只是"规则函数返回了预期结果"。
 */
class McpConnectorEndToEndTest {

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void connectsPullsToolSurfaceAndDetectsPoisonedTool() {
        ServerTarget target = new ServerTarget("test-server",
                System.getProperty("java.home") + File.separator + "bin" + File.separator + "java",
                List.of("-cp", System.getProperty("java.class.path"), TestMcpServer.class.getName()));

        McpConnector.Result result = McpConnector.connect(target);

        assertTrue(result.ok(), "连接应成功，实际错误：" + result.error());
        ToolSurface surface = result.surface();
        assertNotNull(surface);
        assertEquals(2, surface.tools().size(), "应拉回 2 个工具");
        assertTrue(surface.tools().stream().anyMatch(t -> t.name().equals("get_account_balance")));
        assertTrue(surface.fingerprint().length() == 64, "工具面指纹应为 SHA-256");

        // 这正是这个工具存在的意义：把投毒工具从一份"看起来正常"的工具面里挑出来
        List<Finding> findings = RiskRules.evaluate(surface);
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("HIDDEN_INSTRUCTION")
                        && f.toolName().equals("format_helper")),
                "应检出 format_helper 描述中的注入指令：" + findings);
        assertTrue(findings.stream().noneMatch(f -> f.toolName().equals("get_account_balance")),
                "正常工具不应被误报：" + findings);
    }

    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    void connectionFailureIsReportedNotThrown() {
        // 扫描器本身要能在目标不可用时给出可读诊断，而不是甩堆栈
        ServerTarget broken = new ServerTarget("broken", "definitely-not-a-real-command-xyz", List.of());

        McpConnector.Result result = McpConnector.connect(broken);

        assertTrue(!result.ok());
        assertNotNull(result.error());
    }
}
