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
    @Test fun `only zero-config checks are offered and peer-dependent TURN tests are excluded`() {
        // Drives both the Assessment tab and Run All's automatic path.
        val auto = TestRegistry.automaticTests
        assertEquals(TestRegistry.passiveTests + TestRegistry.automaticProtocolTests, auto)
        assertEquals(TestRegistry.passiveTests + TestRegistry.protocolTests, TestRegistry.executable())
        assertTrue(setOf("TRN-04", "TRN-05").all { it in TestRegistry.executable() })
        // A second allocation on the same server is the receiving peer, so no echo host is needed.
        assertTrue("TRN-04" in auto)
        assertTrue("TRN-05" in auto)
        assertFalse("SIG-02" in auto) // needs a recorded scenario
        assertFalse("SIG-07" in auto) // manual / paired backlog, no adapter
        assertTrue(auto.all { TestRegistry.capability(it, AssessmentConfig()) in setOf("Passive analysis", "Built-in TURN runner") })
    }
    @Test fun `configured scenarios gain an execution row and manual backlog items do not`() {
        val step = ScenarioStep("control", "https://app.test/", assertion = Assertion("/body", JsonPrimitive("private")))
        val scenario = Scenario("auth", "SIG-02", "Authentication", "private response", control = listOf(step), cases = listOf(ScenarioCase("absent", listOf(step))))
        assertFalse("SIG-02" in TestRegistry.executable())
        assertTrue("SIG-02" in TestRegistry.executable(AssessmentConfig(scenarios = listOf(scenario))))
        assertFalse("SIG-07" in TestRegistry.executable())
        val report = webrtc.report.AssessmentReport.markdown(AssessmentConfig(), emptyList())
        assertContains(report, "TRN-04")
        assertFalse(report.contains("SIG-07"))
        assertFalse(report.contains("Selected"))
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
