package webrtc

import kotlin.test.Test
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
        assertTrue(message.startsWith("WebRTC Test Suite v"), message)
        assertTrue(message.endsWith(" loaded"), message)
    }
}
