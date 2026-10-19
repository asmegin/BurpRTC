package webrtc.datachannel

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*
import org.junit.Assume.assumeTrue
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import kotlin.test.*

/** Opt-in: set CHROME_PATH to a Chromium-based browser. Uses a temporary profile and data: URLs only. */
class BrowserRunnerLiveTest {
    @Test fun `launches a session, tags new documents before page scripts and runs call-control steps`() {
        val path = System.getenv("CHROME_PATH").orEmpty()
        assumeTrue("Set CHROME_PATH to run the live browser runner test", path.isNotBlank())
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ -> if (method.returnType.isInterface) proxy(method.returnType) else null }
        val store = ConfigStore(proxy(MontoyaApi::class.java) as MontoyaApi)
        store.save(store.config.copy(browserRunner = BrowserRunnerConfig(browserPath = path, proxy = "127.0.0.1:9", headless = true, keepProfiles = false)))
        val telemetry = TelemetryTableModel()
        val runner = BrowserRunner(store, ActiveTestController(store, { false }, telemetry), telemetry)
        try {
            val live = runner.launch(RunnerSession("live-test"))
            live.cdp.call("Page.navigate", buildJsonObject { put("url", "data:text/html,<script>window.seen=window.__WRTC_RUNNER_SESSION__</script><input id=n><button id=b onclick=\"document.title=document.getElementById('n').value\">go</button>") }, live.page)
            runner.runSteps("live-test", "join", literal = "wait button#b 10000\nfill input#n | joined\nclick button#b\nwaitjs document.title === 'joined' 5000")
            assertEquals("live-test", (runner.evaluate("live-test", "window.seen") as JsonPrimitive).content)
            assertEquals(2, (runner.evaluate("live-test", "1 + 1") as JsonPrimitive).int)
            assertFailsWith<IllegalStateException> { runner.runSteps("live-test", "join", literal = "click #missing") }
            assertTrue(telemetry.snapshot().any { it.type == "runner-action" && it.summary.contains("Launched") })
        } finally { runner.closeAll() }
        assertFalse(runner.isRunning("live-test"))
    }
}
