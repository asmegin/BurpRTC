package webrtc.assessment

import kotlinx.serialization.json.*
import webrtc.report.EvidenceFormatting
import webrtc.workflow.RtcDecoder
import kotlin.test.*

class AssessmentTest {
    @Test fun `registry has one stable ID per requirement`() {
        assertEquals(83, TestRegistry.definitions.size)
        assertEquals(TestRegistry.definitions.size, TestRegistry.byId.size)
        assertTrue(TestRegistry.definitions.all { it.contract.isNotBlank() && it.title.isNotBlank() })
    }
    @Test fun `status and upgrade acceptance cannot masquerade as protected effects`() {
        val step = ScenarioStep("get", "https://app.test/", assertion = Assertion("/status", JsonPrimitive(200)))
        assertFailsWith<IllegalArgumentException> { Scenario("s", "SIG-02", "auth", "private", control = listOf(step), cases = listOf(ScenarioCase("absent", listOf(step)))).validate() }
        assertFailsWith<IllegalArgumentException> { TestOutcome(engagementId = "e", testId = "SIG-02", target = "t", backend = "b",
            execution = "completed", security = "policy-violation").validate() }
    }
    @Test fun `escaped socket io SDP credentials and tenant IDs are decoded with bounds`() {
        val sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n"
        val message = "42" + buildJsonArray {
            add("join"); add(buildJsonObject {
                put("roomId", "one"); put("nested", buildJsonObject { put("sdp", sdp) }.toString())
                put("iceServers", buildJsonArray { add(buildJsonObject { put("urls", "turn:turn.test"); put("username", "alice"); put("credential", "full password") }) })
            })
        }
        val decoded = RtcDecoder.decode(message)
        assertEquals(listOf(sdp), decoded.sdps)
        assertEquals("full password", decoded.iceServers.single()["credential"]!!.jsonPrimitive.content)
        assertEquals(listOf("one"), decoded.identifiers["roomId"])
        assertFalse(decoded.sip)
        assertTrue(RtcDecoder.decode("x".repeat(262145)).truncated)
    }
    @Test fun `spreadsheet and markdown rendering are inert without masking raw values`() {
        assertEquals("\"'=CMD(\"\"secret\"\")\"", EvidenceFormatting.csv("=CMD(\"secret\")"))
        assertEquals("\"plain secret\"", EvidenceFormatting.csv("plain secret"))
        assertFalse(EvidenceFormatting.markdown("<script>[x](https://bad)").contains("<script>"))
        val raw = "```\nsecret\n<script>"
        assertTrue(EvidenceFormatting.code(raw).startsWith("````\n"))
        assertContains(EvidenceFormatting.code(raw), raw)
    }
    @Test fun `JSON pointer separates missing and present values`() {
        val obj = buildJsonObject { put("a/b", buildJsonArray { add("secret") }) }
        assertEquals(JsonPrimitive("secret"), JsonPointer.get(obj, "/a~1b/0"))
        assertNull(JsonPointer.get(obj, "/a~1b/1"))
    }
}
