package webrtc.ui

import burp.api.montoya.MontoyaApi
import webrtc.assessment.*
import webrtc.authz.AuthzMatrixRunner
import webrtc.bridge.ActiveTestController
import webrtc.config.*
import webrtc.protocol.ProtocolRunner
import webrtc.scope.ScopeGate
import webrtc.telemetry.TelemetryTableModel
import webrtc.tls.TlsScanRunner
import webrtc.workflow.RequestCatalog
import java.awt.Component
import java.awt.Container
import java.awt.Rectangle
import java.lang.reflect.Proxy
import java.nio.file.Path
import javax.swing.*
import kotlin.test.*

/** Navigation and saved inputs affect which scans run; exercise those behaviors on the EDT. */
class WorkspaceTest {
    private class Fixture {
        val values = mutableMapOf<String, String>()
        var networkCalls = 0
        private fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "sendRequest" || method.name == "createWebSocket" -> { networkCalls++; error("UI must not start network work") }
                method.name == "getString" -> values[args!![0]]
                method.name == "setString" -> { values[args!![0] as String] = args[1] as String; null }
                method.returnType == Boolean::class.javaPrimitiveType -> false
                method.returnType.isInterface -> proxy(method.returnType)
                else -> null
            }
        }
        val api = proxy(MontoyaApi::class.java) as MontoyaApi
        val store = ConfigStore(api)
        val telemetry = TelemetryTableModel()
        val active = ActiveTestController(store, { false }, telemetry)
        val outcomes = OutcomeStore(api, telemetry) { store.config.assessment.engagementId }
        val protocol = ProtocolRunner(store, NetworkAuthorization(store) { false }, outcomes)
        val checks = AssessmentController(store, outcomes, protocol, telemetry)
        val tls = TlsScanRunner(store, { false }, telemetry, Path.of("build", "ui-test-tls"), { error("UI must not launch Python") })
        fun suite() = SuiteTab(api, store, telemetry, AuthzMatrixRunner(api, store, ScopeGate(api)), active, tls, checks, RequestCatalog(),
            canaries = webrtc.canary.CanaryRegistry({ null }, {}, telemetry)) {}
    }
    private fun descendants(root: Component): List<Component> = listOf(root) +
        if (root is Container) root.components.flatMap { descendants(it) } else emptyList()
    private fun layout(root: Component) {
        if (root is Container) { root.doLayout(); root.components.forEach { layout(it) } }
    }
    private fun assertVisibleAction(root: JComponent, label: String) {
        val button = descendants(root).filterIsInstance<JButton>().single { it.text == label }
        val bounds = SwingUtilities.convertRectangle(button.parent, button.bounds, root)
        assertTrue(Rectangle(0, 0, root.width, root.height).contains(bounds), "$label must fit the workspace: $bounds")
        var parent = button.parent
        while (parent != null && parent !== root) {
            if (parent is JViewport) assertTrue(Rectangle(0, 0, parent.width, parent.height)
                .contains(SwingUtilities.convertRectangle(button.parent, button.bounds, parent)), "$label must remain outside clipped scroll content")
            parent = parent.parent
        }
    }

    @Test fun `every screen opens without running a scan and primary actions fit a compact workspace`() {
        SwingUtilities.invokeAndWait {
            val f = Fixture(); val suite = f.suite()
            suite.setSize(1000, 680); suite.addNotify()
            try {
                val screens = linkedMapOf("scan" to "Scan selected", "setup" to "Check configuration", "evidence" to "Capture live stats",
                    "report" to "Generate report", "security" to "Run checks", "tls" to "Run TLS tests", "access" to "Send to Repeater",
                    "mutation" to null, "sdp" to "Run SDP fuzzing", "data" to "Run payloads", "ice" to "Gather candidates",
                    "loop" to "Run negotiation loop", "external" to "Copy command", "canaries" to "Generate canary")
                screens.forEach { (id, action) ->
                    suite.navigate(id); repeat(6) { layout(suite) }
                    assertEquals(id, suite.selectedScreenId)
                    // Find only the visible card: cached screens intentionally retain their controls.
                    val cards = suite.components.filterIsInstance<JPanel>().single { it.layout is java.awt.CardLayout }
                    val card = cards.components.filterIsInstance<JPanel>().single { it.isVisible }
                    action?.let { assertVisibleAction(card, it) }
                }
                assertEquals(0, f.networkCalls)
                assertTrue(f.telemetry.snapshot().isEmpty())
            } finally { suite.removeNotify(); f.protocol.close(); f.tls.close() }
        }
    }
    @Test fun `navigation preserves unsaved inputs and unrelated config changes preserve Python drafts`() {
        val f = Fixture()
        lateinit var original: JTextField
        lateinit var suite: SuiteTab
        SwingUtilities.invokeAndWait {
            suite = f.suite(); suite.navigate("tls")
            original = descendants(suite).filterIsInstance<JTextField>().single { it.accessibleContext.accessibleName == "Python executable:" }
            original.text = "C:\\draft\\python.exe"
            suite.navigate("report"); suite.navigate("tls")
            assertSame(original, descendants(suite).filterIsInstance<JTextField>().single { it.accessibleContext.accessibleName == "Python executable:" })
            f.store.save(f.store.config.copy(scanPlan = ScanPlan(emptySet())))
        }
        SwingUtilities.invokeAndWait { assertEquals("C:\\draft\\python.exe", original.text) }
    }
    @Test fun `SDP budget restores exactly and saving settings does not execute a test`() {
        SwingUtilities.invokeAndWait {
            val f = Fixture()
            f.store.save(f.store.config.copy(sdpFuzz = SdpFuzzConfig(maxCases = 10)))
            val panel = SdpFuzzPanel(f.store, f.active, f.telemetry)
            val budget = descendants(panel).filterIsInstance<JSpinner>().single()
            assertEquals(10, budget.value)
            budget.value = 25
            descendants(panel).filterIsInstance<JButton>().single { it.text == "Save settings" }.doClick()
            assertEquals(25, f.store.load().sdpFuzz.maxCases)
            assertFalse(descendants(panel).filterIsInstance<JButton>().single { it.text == "Run SDP fuzzing" }.isEnabled)
            assertEquals(0, f.networkCalls); assertTrue(f.telemetry.snapshot().isEmpty())
        }
    }
    @Test fun `TURN credential remains visible and saving preserves it exactly`() {
        SwingUtilities.invokeAndWait {
            val f = Fixture(); val panel = IceProbePanel(f.store, f.active, f.telemetry)
            val credential = descendants(panel).filterIsInstance<JTextField>().single { it.accessibleContext.accessibleName == "TURN credential:" }
            assertFalse(credential is JPasswordField)
            credential.text = " raw secret with spaces "
            descendants(panel).filterIsInstance<JButton>().single { it.text == "Save settings" }.doClick()
            assertEquals(" raw secret with spaces ", f.store.load().iceProbe.credential)
            assertTrue(f.telemetry.snapshot().isEmpty())
        }
    }
}
