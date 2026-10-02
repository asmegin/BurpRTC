package webrtc.telemetry

import kotlinx.serialization.json.*
import webrtc.config.Detectors
import webrtc.config.SdpDocument
import kotlin.test.*

class EvidenceAnalysisTest {
    private fun event(seq: Long, type: String, pc: String = "p", generation: Int = 1, extra: JsonObjectBuilder.() -> Unit = {}) =
        TelemetryEvent(seq, "2026-10-02T00:00:00Z", type, "https://app.test/call", pc, false, "", buildJsonObject {
            put("type", type); put("agent", "a"); put("generation", generation); extra()
        }.toString())
    private fun sdp(fingerprint: String = "AA:BB", mid: String = "a") = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:$mid\r\na=fingerprint:sha-256 $fingerprint\r\na=rtpmap:96 opus/48000/2\r\na=rtcp-mux\r\n"

    @Test fun `relay addresses and mixed peer policies cannot yield blanket privacy pass`() {
        val all = listOf(event(1, "pc-new") { put("iceTransportPolicy", "relay") },
            event(2, "ice") { put("candidate", "candidate:1 1 udp 1 8.8.8.8 5000 typ relay raddr 10.1.1.1 rport 2") },
            event(3, "ice", pc = "other") { put("candidate", "candidate:1 1 udp 1 8.8.4.4 5000 typ srflx") },
            event(4, "ice") { put("candidate", "candidate:1 1 udp 1 8.8.4.4 5000 typ host") })
        val reviews = EvidenceAnalysis.privacy(all)
        assertContains(reviews[0].text, "relay infrastructure")
        assertFalse(reviews[0].policyMismatch)
        assertContains(reviews[1].text, "policy=unknown")
        assertTrue(reviews[2].policyMismatch)
    }
    @Test fun `certificate binding cannot borrow another peer direction generation or MID`() {
        val descriptions = listOf(event(1, "sdp-remote", "other") { put("sdp", sdp("AA:BB")) },
            event(2, "sdp-local") { put("sdp", sdp("AA:BB")) },
            event(3, "sdp-remote", generation = 2) { put("sdp", sdp("AA:BB")) },
            event(4, "sdp-remote") { put("sdp", sdp("CC:DD") + "m=video 9 UDP/TLS/RTP/SAVPF 97\r\na=mid:v\r\na=fingerprint:sha-256 AA:BB\r\n") })
        val cert = event(5, "dtls-cert") { put("role", "remote"); put("mids", buildJsonArray { add("a") }) }
        assertEquals(listOf("sha-256" to "CC:DD"), EvidenceAnalysis.binding(cert, descriptions).fingerprints)
        assertTrue(EvidenceAnalysis.binding(event(6, "dtls-cert", generation = 3) { put("role", "remote") }, descriptions).fingerprints.isEmpty())
        assertTrue(EvidenceAnalysis.binding(event(6, "dtls-cert") { put("role", "remote") }, descriptions).fingerprints.isEmpty())
    }
    @Test fun `ICE credentials inherit across distant attributes and only explicit restarts require rotation`() {
        val old = "v=0\r\na=ice-ufrag:abcd\r\na=setup:actpass\r\na=fingerprint:sha-256 AA\r\na=ice-pwd:0123456789012345678901\r\nm=audio 9 RTP/SAVPF 0\r\na=mid:audio\r\n"
        assertEquals("abcd", SdpDocument.parse(old).credentials().getValue("audio").ufrag)
        val before = event(1, "sdp-local") { put("kind", "offer"); put("sdp", old) }
        val ordinary = event(2, "sdp-local") { put("kind", "offer"); put("sdp", old) }
        assertTrue(EvidenceAnalysis.restartIssues(listOf(before, ordinary)).isEmpty())
        val restart = event(3, "sdp-local", generation = 2) { put("kind", "offer"); put("sdp", old.replace("abcd", "efgh")); put("iceRestart", true) }
        assertEquals(1, EvidenceAnalysis.restartIssues(listOf(before, restart)).size)
    }
    @Test fun `SDP payload mappings and fingerprint inheritance are scoped to media`() {
        val text = sdp() + "a=fmtp:96 minptime=10\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v\r\na=rtpmap:96 H264/90000\r\n" +
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=rtpmap:96 fake/8000\r\n"
        assertFalse(Detectors.hasDtlsFingerprint(text))
        val codecs = Detectors.codecDetails(text)
        assertEquals(2, codecs.size)
        assertNull(codecs.single { it.name == "H264" }.fmtp)
        assertContains(codecs.single { it.name == "opus" }.fmtp.orEmpty(), "minptime")
    }
    @Test fun `port zero bundle-only inherits tagged transport while rejected sections are ignored`() {
        val text = "a=group:BUNDLE a v\r\n" + sdp() + "m=video 0 UDP/TLS/RTP/SAVPF 97\r\na=mid:v\r\na=bundle-only\r\na=rtpmap:97 VP8/90000\r\n"
        assertEquals(2, SdpDocument.parse(text).let { it.media.count(it::active) })
        assertTrue(Detectors.hasDtlsFingerprint(text))
        assertEquals(listOf("opus"), Detectors.enumerateCodecs(text.replace("a=bundle-only\r\n", "")))
    }
}
