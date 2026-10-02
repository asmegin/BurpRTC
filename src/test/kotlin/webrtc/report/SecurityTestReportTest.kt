package webrtc.report

import webrtc.authz.AuthzResult
import webrtc.config.WebRtcConfig
import webrtc.config.IdentityProfile
import webrtc.telemetry.TelemetryEvent
import webrtc.workflow.SignalingMetadata
import kotlin.test.*

class SecurityTestReportTest {
    private fun event(seq: Long, type: String, raw: String, peer: String = "pc1") =
        TelemetryEvent(seq, "12:34:56.789", type, "https://app.test/call", peer, false, "$type recorded", raw)
    private fun section(area: SecurityArea, events: List<TelemetryEvent> = emptyList(), authz: List<AuthzResult> = emptyList(), config: WebRtcConfig = WebRtcConfig()) =
        SecurityTestReport.sections(config, events, authz).single { it.area == area }

    @Test fun `empty engagement includes exactly twelve areas with gaps and no successful checks`() {
        val sections = SecurityTestReport.sections(WebRtcConfig(), emptyList(), emptyList())
        assertEquals(SecurityArea.entries.toList(), sections.map { it.area })
        assertEquals(12, sections.size)
        assertTrue(sections.all { it.results.isNotEmpty() })
        assertFalse(sections.flatMap { it.results }.any { it.status in setOf(SecurityTestReport.Status.OBSERVED, SecurityTestReport.Status.COMPLETED) })
        assertTrue(section(SecurityArea.ARCHITECTURE).results.all { it.status == SecurityTestReport.Status.UNSUPPORTED })
        assertTrue(section(SecurityArea.STORAGE).results.all { it.status == SecurityTestReport.Status.UNSUPPORTED })
        val md = SecurityTestReport.markdown(WebRtcConfig(), emptyList(), emptyList())
        SecurityArea.entries.forEachIndexed { index, area -> assertTrue(md.contains("## ${index + 1}. ${area.title}\n")) }
        assertTrue(md.contains("Neither is an overall security pass"))
    }

    @Test fun `configured identities and opt in settings are not results`() {
        val cfg = WebRtcConfig(identities = listOf(IdentityProfile("Alice", mapOf("Authorization" to "Bearer full-secret"))))
        cfg.iceProbe = cfg.iceProbe.copy(url = "turns:relay.test:5349", username = "user", credential = "full-turn-secret")
        cfg.signalingFlood = cfg.signalingFlood.copy(confirm = true)
        val sections = SecurityTestReport.sections(cfg, emptyList(), emptyList())
        assertTrue(sections.single { it.area == SecurityArea.AUTH }.results.any { it.status == SecurityTestReport.Status.NOT_TESTED })
        assertTrue(sections.single { it.area == SecurityArea.DOS }.results.any { it.status == SecurityTestReport.Status.NOT_TESTED })
        assertTrue(sections.single { it.area == SecurityArea.NAT }.results.any { it.status == SecurityTestReport.Status.CONFIGURED && it.detail.contains("full-turn-secret") })
    }

    @Test fun `TLS listener results route to signaling or NAT and failed checks stay incomplete`() {
        val events = listOf(
            event(1, "tls-scan-start", """{"target":"turns:relay.test:5349"}"""),
            event(2, "tls-scan-result", """{"target":"turns:relay.test:5349","result":{"status":"partial","checks":[{"name":"heartbleed","status":"error","summary":"Timeout"}],"findings":[{"level":"finding","text":"TLS 1.0 accepted"}]}}"""),
            event(3, "tls-scan-result", """{"target":"wss://app.test/ws","result":{"status":"completed","checks":[],"findings":[]}}""")
        )
        val nat = section(SecurityArea.NAT, events)
        assertTrue(nat.results.any { it.status == SecurityTestReport.Status.PARTIAL && it.test.startsWith("TCP TLS") })
        assertTrue(nat.results.any { it.status == SecurityTestReport.Status.ERROR && it.test.contains("heartbleed") })
        assertTrue(nat.results.any { it.status == SecurityTestReport.Status.FINDING && it.detail == "TLS 1.0 accepted" })
        assertFalse(nat.results.any { it.status == SecurityTestReport.Status.PENDING })
        assertTrue(section(SecurityArea.SIGNALING, events).results.any { it.status == SecurityTestReport.Status.COMPLETED })
        assertFalse(section(SecurityArea.DTLS, events).results.any { it.evidence.isNotEmpty() })
    }

    @Test fun `jobs without payload results preserve cancelled pending and failed states`() {
        val events = listOf(
            event(1, "test-job", """{"commandId":"run1","module":"dc-fuzz","status":"queued"}"""),
            event(2, "test-job", """{"commandId":"run1","module":"dc-fuzz","status":"cancelled"}"""),
            event(3, "test-job", """{"commandId":"run2","module":"ice-probe","status":"running"}"""),
            event(4, "test-job", """{"commandId":"run3","module":"sdp-fuzz","status":"expired"}"""))
        val dc = section(SecurityArea.DATA, events).results.single { it.test.startsWith("Active run") }
        assertEquals(SecurityTestReport.Status.CANCELLED, dc.status)
        assertEquals(listOf(1L, 2L), dc.evidence)
        assertTrue(section(SecurityArea.NAT, events).results.any { it.status == SecurityTestReport.Status.PENDING })
        assertTrue(section(SecurityArea.SDP, events).results.any { it.status == SecurityTestReport.Status.ERROR })
    }

    @Test fun `SDP baseline controls parser acceptance and incomplete summaries are distinct`() {
        val events = listOf(
            event(1, "sdp-fuzz-result", """{"commandId":"run","label":"baseline-observed","outcome":"rejected","error":"invalid"}"""),
            event(2, "sdp-fuzz-result", """{"commandId":"run","label":"bad-codec","outcome":"accepted","followupOutcome":"answer-generated"}"""),
            event(3, "sdp-fuzz-summary", """{"commandId":"run","cases":3}"""))
        val results = section(SecurityArea.SDP, events).results
        assertTrue(results.any { it.test.contains("baseline") && it.status == SecurityTestReport.Status.ERROR })
        assertTrue(results.any { it.test.contains("bad-codec") && it.status == SecurityTestReport.Status.REVIEW })
        assertTrue(results.any { it.test.contains("summary") && it.status == SecurityTestReport.Status.PARTIAL })
        assertFalse(results.any { it.status == SecurityTestReport.Status.FINDING })
    }

    @Test fun `NAT timeout and DataChannel closure and send acceptance do not prove security or DoS`() {
        val events = listOf(
            event(1, "ice-probe-result", """{"reason":"timeout","observed":false,"counts":{"relay":0}}"""),
            event(2, "dc-state", """{"channelId":"dc1","state":"closed","everOpened":false}"""),
            event(3, "fuzz-result", """{"channelId":"dc1","accepted":true,"bytes":42}"""))
        assertTrue(section(SecurityArea.NAT, events).results.any { it.status == SecurityTestReport.Status.ERROR })
        val dc = section(SecurityArea.DATA, events)
        assertTrue(dc.results.any { it.status == SecurityTestReport.Status.REVIEW })
        assertTrue(dc.results.any { it.status == SecurityTestReport.Status.OBSERVED && it.detail.contains("does not prove remote") })
        assertFalse(section(SecurityArea.DOS, events).results.any { it.status == SecurityTestReport.Status.COMPLETED })
    }

    @Test fun `media cipher findings are separate from DTLS and DataChannel only SRTP is not applicable`() {
        val crypto = event(1, "crypto", """{"detail":"dtls=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 srtp=SRTP_NULL_HMAC_SHA1_80 tls=DTLS1.2"}""")
        assertTrue(section(SecurityArea.MEDIA, listOf(crypto)).results.any { it.status == SecurityTestReport.Status.FINDING })
        assertFalse(section(SecurityArea.DTLS, listOf(crypto)).results.any { it.status == SecurityTestReport.Status.FINDING })
        val sdp = event(2, "sdp-remote", """{"sdp":"v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"}""")
        assertTrue(section(SecurityArea.MEDIA, listOf(crypto, sdp)).results.any { it.status == SecurityTestReport.Status.NOT_APPLICABLE })
    }

    @Test fun `invalid certificates and malformed crypto remain unknown instead of passed`() {
        val events = listOf(event(1, "dtls-cert", """{"role":"remote","base64":"invalid"}"""), event(2, "crypto", "not json"))
        assertTrue(section(SecurityArea.DTLS, events).results.any { it.status == SecurityTestReport.Status.ERROR })
        assertTrue(section(SecurityArea.MEDIA, events).results.any { it.status == SecurityTestReport.Status.PARTIAL })
    }

    @Test fun `authorization replays include every variant full URL hashes and conservative outcomes`() {
        val results = listOf(
            AuthzResult("https://app.test/item?token=full-secret", "unauth", 200, 150, "body-hash", true, true, "auth stripped", null),
            AuthzResult("https://app.test/item", "identity:Bob", 403, 12, "denied", false, false, "other principal", null),
            AuthzResult("https://app.test/item", "SKIPPED", 0, 0, "", false, false, "out of scope", null))
        val auth = section(SecurityArea.AUTH, authz = results)
        assertTrue(auth.results.any { it.status == SecurityTestReport.Status.REVIEW && it.detail.contains("full-secret") && it.detail.contains("body-hash") })
        assertTrue(auth.results.any { it.status == SecurityTestReport.Status.SKIPPED })
        assertEquals(3, auth.results.count { it.authzIndex != null })
        assertFalse(auth.results.any { it.status == SecurityTestReport.Status.FINDING })
        val md = SecurityTestReport.markdown(WebRtcConfig(), emptyList(), results)
        assertTrue(md.contains("[Authz 1](#authz-1)"))
        assertTrue(md.contains("<a id=\"authz-1\"></a>"))
    }

    @Test fun `browser permission and local flood results describe observed limits`() {
        val events = listOf(
            event(1, "getUserMedia-result", """{"outcome":"resolved"}"""),
            event(2, "signaling-flood-summary", """{"attempts":3,"reusedCredentials":0}"""))
        assertTrue(section(SecurityArea.CLIENT, events).results.any { it.status == SecurityTestReport.Status.OBSERVED && it.detail.contains("not a bypass") })
        assertTrue(section(SecurityArea.DOS, events).results.any { it.status == SecurityTestReport.Status.COMPLETED && it.detail.contains("no signaling flood") })
    }

    @Test fun `table escaping and evidence fences preserve raw credentials and before after payloads`() {
        val raw = """{"detail":"payload | [click](bad) ``` unmasked-token","before":"original","after":"changed"}"""
        val event = event(12, "sdp-mutation", raw)
        val md = SecurityTestReport.markdown(WebRtcConfig(), listOf(event), emptyList())
        assertTrue(md.contains("payload &#124; &#91;click&#93;(bad) &#96;&#96;&#96; unmasked-token"))
        assertTrue(md.contains("[#12](#event-12)"))
        assertTrue(md.contains("````json\n$raw\n````"))
        assertEquals(1, Regex("<a id=\"event-12\"></a>").findAll(md).count())
    }

    @Test fun `proxy metadata is observed evidence without asserting WebSocket or SSE tests ran`() {
        val sections = SecurityTestReport.sections(WebRtcConfig(), emptyList(), emptyList(),
            listOf(SignalingMetadata.Endpoint("https://app.test", true, true, 10)))
        val signaling = sections.single { it.area == SecurityArea.SIGNALING }
        assertTrue(signaling.results.any { it.status == SecurityTestReport.Status.OBSERVED && it.detail.contains("10 captured") })
        assertTrue(signaling.results.any { it.status == SecurityTestReport.Status.UNSUPPORTED && it.test.contains("HTTP-SSE") })
    }
}
