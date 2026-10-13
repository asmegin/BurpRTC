package webrtc.ui

import webrtc.authz.*
import java.awt.Component
import java.awt.Container
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.*
import kotlin.test.*

class AuthzPanelTest {
    private fun descendants(root: Component): List<Component> = listOf(root) +
        if (root is Container) root.components.flatMap(::descendants) else emptyList()
    private fun button(panel: AuthzPanel, text: String) = descendants(panel).filterIsInstance<JButton>().single { it.text == text }

    @Test fun `two checked captured sessions compare both resources with donor and absent credentials`() {
        val f = AuthzFixture()
        f.catalog.observe(request("https://app.test/api/alice", headers = mapOf("Authorization" to "Bearer alice")), "application/json", 200)
        f.catalog.observe(request("https://app.test/api/bob", headers = mapOf("Authorization" to "Bearer bob")), "application/json", 200)
        lateinit var panel: AuthzPanel
        val finished = CountDownLatch(1)
        SwingUtilities.invokeAndWait {
            panel = AuthzPanel(f.api, f.config, f.catalog, f.runner)
            assertFalse(button(panel, "Compare selected sessions").isEnabled)
            val sessions = descendants(panel).filterIsInstance<JTable>().single { it.getColumnName(0) == "Use" }
            sessions.model.setValueAt(true, 0, 0); sessions.model.setValueAt(true, 1, 0)
            panel.model.addTableModelListener { if (panel.model.rowCount == 6) finished.countDown() }
        }
        SwingUtilities.invokeAndWait {
            assertTrue(button(panel, "Compare selected sessions").isEnabled)
            assertEquals(2, panel.selectedIdentities().size)
            assertEquals(0, f.sent.size)
            button(panel, "Compare selected sessions").doClick()
        }
        assertTrue(finished.await(5, TimeUnit.SECONDS), "Comparison should finish off the EDT")
        SwingUtilities.invokeAndWait {
            assertEquals(6, f.sent.size)
            assertEquals(listOf("/api/alice", "/api/alice", "/api/alice", "/api/bob", "/api/bob", "/api/bob"), f.sent.map { it.path() })
            assertEquals(listOf("Bearer alice", "Bearer bob", null, "Bearer bob", "Bearer alice", null), f.sent.map { it.headerValue("Authorization") })
            assertEquals(6, panel.model.snapshot().size)
            assertEquals(1, descendants(panel).filterIsInstance<JTabbedPane>().single().selectedIndex)
        }
    }
    @Test fun `capturing and preparing room links do not run network work and config gates disable compare`() {
        val f = AuthzFixture()
        f.catalog.observe(request(headers = mapOf("Cookie" to "session=alice")), "application/json", 200)
        f.catalog.observe(request(headers = mapOf("Cookie" to "session=bob")), "application/json", 200)
        lateinit var panel: AuthzPanel
        SwingUtilities.invokeAndWait {
            panel = AuthzPanel(f.api, f.config, f.catalog, f.runner)
            f.catalog.snapshot().forEach { f.catalog.select(it.id, true) }
        }
        SwingUtilities.invokeAndWait {
            button(panel, "Prepare room swaps").doClick()
            assertEquals(2, descendants(panel).filterIsInstance<JTabbedPane>().single().selectedIndex)
            assertEquals(0, f.sent.size)
            f.config.save(f.config.config.copy(injectionEnabled = false))
        }
        SwingUtilities.invokeAndWait {
            assertFalse(button(panel, "Compare selected sessions").isEnabled)
            assertTrue(button(panel, "Prepare room swaps").isEnabled)
            assertEquals(0, f.sent.size)
        }
    }
}
