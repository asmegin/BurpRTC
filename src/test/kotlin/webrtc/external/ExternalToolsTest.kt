package webrtc.external

import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import webrtc.config.IceProbeConfig
import webrtc.config.WebRtcConfig
import webrtc.telemetry.TelemetryEvent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ExternalToolsTest {

    private val turnServer = ObservedIceServer(
        urls = listOf("turn:turn.example.test:3478?transport=udp"),
        username = "user o'brien",
        credential = "p@ss \$ `x`"
    )
    private val inputs = ExternalInputs(
        pageOrigins = listOf("https://app.example.test/call"),
        iceServers = listOf(turnServer)
    )

    @Test fun `bash quoting preserves spaces quotes dollars and backticks`() {
        assertEquals("'a b'", ExternalTools.bashQuote("a b"))
        assertEquals("'it'\\''s'", ExternalTools.bashQuote("it's"))
        assertEquals("'\$HOME `id` \"x\"'", ExternalTools.bashQuote("\$HOME `id` \"x\""))
    }

    @Test fun `detected TURN values keep credentials in full`() {
        val values = ExternalTools.buildValues(inputs, emptyMap())
        assertEquals("turn.example.test:3478", values["TURN_ENDPOINT"])
        assertEquals("udp", values["TURN_PROTOCOL"])
        assertEquals("user o'brien", values["TURN_USER"])
        assertEquals("p@ss \$ `x`", values["TURN_PASSWORD"])
        assertEquals("app.example.test", values["TARGET_HOST"])
        assertEquals("app.example.test:443", values["TLS_ENDPOINT"])
    }

    @Test fun `catalogue has ten tools and TURN recipes become ready`() {
        val recipes = ExternalTools.catalogue(inputs, emptyMap())
        assertEquals(10, recipes.map { it.tool }.distinct().size, recipes.map { it.tool }.distinct().toString())
        val range = recipes.first { it.id == "stunner-range" }
        assertTrue(range.ready, "missing=${range.missing}")
        assertTrue(range.command.contains("TURN_ENDPOINT='turn.example.test:3478'"), range.command)
        // Single-quoted assignment keeps the credential literal and unaltered.
        assertTrue(range.command.contains("TURN_PASSWORD='p@ss \$ `x`'"), range.command)
        assertTrue(range.command.contains("stunner range-scan"))
    }

    @Test fun `undetected inputs stay visibly incomplete instead of being invented`() {
        val recipes = ExternalTools.catalogue(ExternalInputs(emptyList(), emptyList()), emptyMap())
        val range = recipes.first { it.id == "stunner-range" }
        assertFalse(range.ready)
        assertTrue(range.missing.contains("TURN_ENDPOINT"))
        assertTrue(range.command.contains("<TURN_ENDPOINT>"), range.command)
        assertTrue(range.command.contains("Missing inputs"), range.command)
    }

    @Test fun `manual entries override detection without masking`() {
        val recipes = ExternalTools.catalogue(inputs, mapOf("turn_user" to "alice", "test_peer_ip" to "203.0.113.10"))
        val tcp = recipes.first { it.id == "stunner-tcp" }
        assertTrue(tcp.command.contains("TURN_USER='alice'"), tcp.command)
        assertTrue(tcp.command.contains("TEST_PEER_IP='203.0.113.10'"), tcp.command)
    }

    @Test fun `turnt config renders the observed endpoint and credentials`() {
        val yaml = assertNotNull(ExternalTools.turntConfig(ExternalTools.buildValues(inputs, emptyMap())))
        assertTrue(yaml.contains("turn:turn.example.test:3478?transport=udp"), yaml)
        assertTrue(yaml.contains("user o'brien"), yaml)
        assertTrue(yaml.contains("p@ss \$ `x`"), yaml)
    }

    @Test fun `detect parses pc-new ICE servers and the Config probe`() {
        val detail = buildJsonObject {
            put("iceServers", buildJsonArray {
                add(buildJsonObject {
                    put("urls", buildJsonArray { add("turn:observed.example.test:3478"); add("stun:observed.example.test:3478") })
                    put("username", "observed-user")
                    put("credential", "observed-pass")
                })
            })
        }.toString()
        val raw = buildJsonObject { put("type", "pc-new"); put("detail", detail) }.toString()
        val event = TelemetryEvent(1, "t", "pc-new", "https://app.example.test/call", "pc1", false, "s", raw)
        val config = WebRtcConfig(iceProbe = IceProbeConfig(url = "turn:config.example.test:3478", username = "cfg-user", credential = "cfg-pass"))

        val detected = ExternalInputs.detect(config, listOf(event))
        assertEquals(2, detected.iceServers.size)
        val observed = detected.iceServers.first { it.username == "observed-user" }
        assertEquals(listOf("turn:observed.example.test:3478", "stun:observed.example.test:3478"), observed.urls)
        assertEquals("observed-pass", observed.credential)
        assertTrue(detected.iceServers.any { it.username == "cfg-user" && it.credential == "cfg-pass" })
        assertTrue(detected.pageOrigins.contains("https://app.example.test/call"))
    }

    @Test fun `markdown guide includes commands and credentials`() {
        val markdown = ExternalTools.toMarkdown(ExternalTools.catalogue(inputs, emptyMap()))
        assertTrue(markdown.contains("```bash"))
        assertTrue(markdown.contains("TURN_USER=${ExternalTools.bashQuote("user o'brien")}"), markdown)
        assertTrue(markdown.contains("TURN_PASSWORD=${ExternalTools.bashQuote("p@ss \$ `x`")}"), markdown)
    }
}
