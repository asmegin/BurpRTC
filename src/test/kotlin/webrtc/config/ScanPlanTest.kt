package webrtc.config

import burp.api.montoya.MontoyaApi
import java.lang.reflect.Proxy
import javax.swing.JTable
import javax.swing.SwingUtilities
import webrtc.ui.ScanSelectionPanel
import kotlin.test.*

class ScanPlanTest {
    private var persisted: String? = null
    // Per-installation preferences (local program paths) are stored apart from the project.
    private val preferences = HashMap<String, String>()
    private fun store(): ConfigStore {
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "getString" -> (args!![0] as String).let { if (it.startsWith("burprtc.")) preferences[it] else persisted }
                method.name == "setString" -> { (args!![0] as String).let { if (it.startsWith("burprtc.")) preferences[it] = args[1] as String else persisted = args[1] as String }; null }
                method.returnType.isInterface -> proxy(method.returnType)
                else -> null
            }
        }
        return ConfigStore(proxy(MontoyaApi::class.java) as MontoyaApi)
    }
    @Test fun `new and legacy projects select all runnable modules`() {
        assertTrue(store().config.scanPlan.let { plan -> ScanModule.entries.all { plan.includes(it) } })
        persisted = """{"scanPlan":{"enabled":["passive","stats","ice","sdp","data"]}}"""
        assertEquals(ScanPlan(), store().config.scanPlan)
    }
    @Test fun `a project file cannot choose local programs or files`() {
        persisted = """{"agentJsPath":"C:/secret.txt","tlsScan":{"pythonExecutable":"evil.exe"},"browserRunner":{"browserPath":"evil.exe"}}"""
        val loaded = store().config
        assertEquals("", loaded.agentJsPath)
        assertEquals("python", loaded.tlsScan.pythonExecutable)
        assertEquals("", loaded.browserRunner.browserPath)
        val store = store()
        store.save(store.config.copy(agentJsPath = "C:/agent.js", browserRunner = store.config.browserRunner.copy(browserPath = "C:/chrome.exe")))
        assertFalse(persisted!!.contains("agent.js") || persisted!!.contains("chrome.exe"))
        assertEquals("C:/agent.js", store.load().agentJsPath)
        assertEquals("C:/chrome.exe", store.load().browserRunner.browserPath)
    }
    @Test fun `an explicit empty selection survives project reload`() {
        val store = store()
        store.save(store.config.copy(scanPlan = ScanPlan(emptySet())))
        assertTrue(store.load().scanPlan.enabled.isEmpty())
        assertEquals(ScanPlan.CURRENT_VERSION, store.load().scanPlan.selectionVersion)
    }
    @Test fun `version 2 selections gain the new modules once while an empty selection stays empty`() {
        persisted = """{"scanPlan":{"enabled":["passive","authz"],"selectionVersion":2}}"""
        val upgraded = store().config.scanPlan
        assertEquals(setOf("passive", "authz", "browser", "invites", "artifacts", "dc-runner"), upgraded.enabled)
        assertEquals(ScanPlan.CURRENT_VERSION, upgraded.selectionVersion)
        persisted = """{"scanPlan":{"enabled":["passive"],"selectionVersion":3}}"""
        assertEquals(setOf("passive", "dc-runner"), store().config.scanPlan.enabled)
        persisted = """{"scanPlan":{"enabled":[],"selectionVersion":2}}"""
        assertTrue(store().config.scanPlan.enabled.isEmpty())
    }
    @Test fun `first tab checkboxes persist selection and disabling mutation stops saved rules`() {
        val store = store()
        store.save(store.config.copy(sdpMutation = SdpMutationConfig(enabled = true, removeFingerprint = true)))
        SwingUtilities.invokeAndWait {
            val panel = ScanSelectionPanel(store)
            val scroll = panel.components.filterIsInstance<javax.swing.JScrollPane>().single()
            val table = scroll.viewport.view as JTable
            assertTrue((0 until table.rowCount).all { table.getValueAt(it, 0) == true })
            table.setValueAt(false, ScanModule.entries.indexOf(ScanModule.MUTATION), 0)
            assertFalse(store.config.sdpMutation.enabled)
            assertFalse(store.load().scanPlan.includes(ScanModule.MUTATION))
            assertTrue(store.load().scanPlan.includes(ScanModule.TLS))
            panel.setRunning(true)
            assertFalse(table.isCellEditable(0, 0))
        }
    }
}
