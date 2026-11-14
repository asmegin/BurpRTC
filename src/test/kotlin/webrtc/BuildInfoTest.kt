package webrtc

import webrtc.ui.UiKit
import javax.swing.Timer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BuildInfoTest {

    @Test fun `version comes from build metadata and is not hard-coded blank`() {
        assertTrue(
            BuildInfo.version.matches(Regex("\\d+\\.\\d+\\.\\d+.*|dev")),
            "unexpected version: ${BuildInfo.version}"
        )
    }

    @Test fun `loaded message names the extension and version`() {
        val message = BuildInfo.loadedMessage()
        assertTrue(message.startsWith("BurpRTC v"), message)
        assertTrue(message.endsWith(" loaded"), message)
    }

    @Test fun `safeToolTip neutralizes Swing BasicHTML and bounds tooltip length`() {
        assertNull(UiKit.safeToolTip(null))
        assertNull(UiKit.safeToolTip(""))
        assertEquals("plain text", UiKit.safeToolTip("plain text"))
        val html = UiKit.safeToolTip("  <HTML><img src='http://attacker.example/leak'>")!!
        assertFalse(html.trimStart().startsWith("<html", ignoreCase = true))
        assertTrue(html.startsWith("\u200B"))
        assertEquals(513, UiKit.safeToolTip("a".repeat(1000))!!.length)
    }

    @Test fun `stopAllTimers stops registered Swing timers on unload`() {
        val timer = UiKit.registerTimer(Timer(10_000) {}.apply { start() })
        assertTrue(timer.isRunning)
        UiKit.stopAllTimers()
        assertFalse(timer.isRunning)
    }
}
