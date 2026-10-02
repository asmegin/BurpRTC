package webrtc.report

import webrtc.authz.AuthzResult
import webrtc.config.WebRtcConfig
import webrtc.telemetry.TelemetryEvent
import kotlin.test.*

class CoverageChecklistTest {
    private fun event(seq: Long, type: String, raw: String) =
        TelemetryEvent(seq, "12:00:00", type, "https://app.test/call", "pc1", false, type, raw)
    private fun checklist(events: List<TelemetryEvent> = emptyList(), authz: List<AuthzResult> = emptyList()) =
        SecurityTestReport.checklist(SecurityTestReport.sections(WebRtcConfig(), events, authz))
    private fun check(id: CoverageCheck, events: List<TelemetryEvent> = emptyList(), authz: List<AuthzResult> = emptyList()) =
        checklist(events, authz).single { it.check == id }

    @Test fun `empty engagement lists every requested item and extra categories before evidence`() {
        val summary = checklist()
        assertEquals(CoverageCheck.entries.toList(), summary.map { it.check })
        assertTrue(summary.all { it.results.isNotEmpty() })
        assertTrue(summary.flatMap { it.results }.all { it.status in setOf(SecurityTestReport.Status.NOT_TESTED, SecurityTestReport.Status.UNSUPPORTED) })
        val md = SecurityTestReport.markdown(WebRtcConfig(), emptyList(), emptyList())
        assertTrue(md.indexOf("## Security checklist") < md.indexOf("## Security test results"))
        CoverageGroup.entries.forEach { assertTrue(md.contains("### ${it.title}\n\n")) }
        listOf("Signaling authentication tests", "WebSocket authentication tests", "TURN server authentication tests",
            "SRTP authentication tests", "TLS version security checks", "Cipher-Suite security analysis", "TURN relay abuse tests",
            "DTLS certificate analysis", "DTLS Crypto-Suite analysis", "SRTP security tests", "RTP injection", "RTP bleed", "RTP flooding",
            "RTP packet fuzzing", "Codec fuzzing", "Codec enumeration", "Signalling black box fuzzing", "Signaling denial of service testing",
            "API flooding", "SIP security tests over WebSocket", "Injection security tests", "API security tests where applicable")
            .forEach { assertTrue(md.contains("- **$it**"), it) }
        assertEquals(2, Regex("- \\*\\*RTP packet fuzzing\\*\\*").findAll(md).count())
        assertEquals(2, Regex("- \\*\\*Codec fuzzing\\*\\*").findAll(md).count())
        CoverageCheck.entries.forEach { assertEquals(1, Regex("<a id=\"check-${it.name.lowercase()}\"></a>").findAll(md).count()) }
    }

    @Test fun `host and STUN gatherings never count as TURN authentication or abuse tests`() {
        val host = event(1, "ice-probe-result", """{"expected":"host","observed":true,"counts":{"host":1,"relay":0}}""")
        val stun = event(2, "ice-probe-result", """{"expected":"srflx","observed":true,"counts":{"srflx":1,"relay":0}}""")
        assertEquals(SecurityTestReport.Status.NOT_TESTED, check(CoverageCheck.TURN_AUTH, listOf(host, stun)).results.single().status)
        val turn = event(3, "ice-probe-result", """{"expected":"relay","observed":true,"counts":{"relay":1}}""")
        val result = check(CoverageCheck.TURN_AUTH, listOf(host, stun, turn))
        assertEquals(listOf(3L), result.results.single().evidence)
        assertEquals(CoverageSupport.PARTIAL, result.check.support)
        assertTrue(result.check.scope.contains("does not automatically compare"))
    }

    @Test fun `TLS completion without protocol checks and unrelated certificate checks do not imply cipher coverage`() {
        val events = listOf(event(1, "tls-scan-result", """{"target":"https://app.test","result":{"status":"completed","checks":[{"name":"certificate_info","status":"completed","summary":"valid"}]}}"""))
        assertEquals(SecurityTestReport.Status.NOT_TESTED, check(CoverageCheck.TLS_VERSION, events).results.single().status)
        assertEquals(SecurityTestReport.Status.NOT_TESTED, check(CoverageCheck.TLS_CIPHER, events).results.single().status)
    }

    @Test fun `TURN failures preserve actual run credentials even when configuration later changes`() {
        val failure = event(1, "ice-probe-error", """{"url":"turn:relay.test","username":"original-user","credential":"original-secret","detail":"setup failed"}""")
        val row = check(CoverageCheck.TURN_AUTH, listOf(failure)).results.single()
        assertEquals(SecurityTestReport.Status.ERROR, row.status)
        assertTrue(row.detail.contains("original-secret"))
        assertTrue(row.detail.contains("turn:relay.test"))
    }

    @Test fun `TLS checklist includes per-protocol failures and findings but no media DTLS evidence`() {
        val events = listOf(event(1, "tls-scan-result", """{"target":"turns:relay.test","result":{"status":"partial","checks":[{"name":"tls_1_0_cipher_suites","status":"completed","summary":"legacy accepted"},{"name":"tls_1_3_cipher_suites","status":"error","summary":"timeout"}],"findings":[{"level":"finding","check":"tls_1_0_cipher_suites","text":"tls 1 0 accepted by the listener"}]}}"""))
        val result = check(CoverageCheck.TLS_VERSION, events)
        assertTrue(result.statuses.contains("Completed: 1"))
        assertTrue(result.statuses.contains("Error: 1"))
        assertTrue(result.statuses.contains("Finding: 1"))
        assertTrue(check(CoverageCheck.DTLS_CIPHER, events).results.all { it.evidence.isEmpty() })
    }

    @Test fun `SDP baseline and generic parser cases do not count as codec fuzzing`() {
        val baseline = event(1, "sdp-fuzz-result", """{"label":"baseline-observed","outcome":"accepted"}""")
        val generic = event(2, "sdp-fuzz-result", """{"label":"line-1-deleted","outcome":"rejected"}""")
        val codec = event(3, "sdp-fuzz-result", """{"label":"line-90-codec-payload-overflow","outcome":"accepted"}""")
        assertEquals(SecurityTestReport.Status.NOT_TESTED, check(CoverageCheck.CODEC_FUZZ, listOf(baseline, generic)).results.single().status)
        val result = check(CoverageCheck.CODEC_FUZZ, listOf(baseline, generic, codec))
        assertEquals(listOf(3L), result.results.single().evidence)
        assertEquals(SecurityTestReport.Status.REVIEW, result.results.single().status)
        assertEquals(CoverageSupport.PARTIAL, result.check.support)
        assertTrue(check(CoverageCheck.RTP_FUZZ, listOf(codec)).results.all { it.status == SecurityTestReport.Status.UNSUPPORTED })
    }

    @Test fun `local flood and crypto telemetry cannot satisfy server API or packet security checks`() {
        val events = listOf(event(1, "signaling-flood-summary", """{"attempts":3}"""),
            event(2, "crypto", """{"detail":"dtls=TLS_AES_128_GCM_SHA256 tls=DTLS1.2 srtp=SRTP_AES128_CM_SHA1_80"}"""))
        listOf(CoverageCheck.RTP_FLOOD, CoverageCheck.API_FLOOD, CoverageCheck.SRTP_AUTH, CoverageCheck.RTP_INJECTION, CoverageCheck.RTP_BLEED)
            .forEach { assertTrue(check(it, events).results.all { row -> row.status == SecurityTestReport.Status.UNSUPPORTED }) }
        assertTrue(check(CoverageCheck.SIGNALING_DOS, events).check.scope.contains("no signaling flood"))
    }

    @Test fun `baseline alone is not an authentication test and HTTP replays never imply WebSocket tests`() {
        val baseline = AuthzResult("https://app.test/api", "baseline", 200, 10, "hash", true, false, "baseline", null)
        val unauth = baseline.copy(variant = "unauth", flagged = true, note = "known headers stripped")
        assertEquals(SecurityTestReport.Status.NOT_TESTED, check(CoverageCheck.SIGNALING_AUTH, authz = listOf(baseline)).results.single().status)
        assertEquals(SecurityTestReport.Status.REVIEW, check(CoverageCheck.SIGNALING_AUTH, authz = listOf(baseline, unauth)).results.single().status)
        assertEquals(SecurityTestReport.Status.UNSUPPORTED, check(CoverageCheck.WEBSOCKET_AUTH, authz = listOf(unauth)).results.single().status)
    }

    @Test fun `cancelled runs retain partial evidence and summary escapes untrusted text`() {
        val events = listOf(event(1, "sdp-fuzz-result", """{"label":"codec-test","outcome":"accepted","detail":"[link](evil) <script> | token-secret"}"""),
            event(2, "test-job", """{"commandId":"run","module":"sdp-fuzz","status":"cancelled"}"""))
        val result = check(CoverageCheck.SIGNALING_FUZZ, events)
        assertTrue(result.statuses.contains("Cancelled"))
        assertTrue(result.statuses.contains("Review required"))
        val md = SecurityTestReport.summaryMarkdown(SecurityTestReport.sections(WebRtcConfig(), events, emptyList()))
        assertFalse(md.contains("<script>"))
        assertTrue(md.contains("&#91;link&#93;(evil) &lt;script&gt; &#124; token-secret"))
    }
}
