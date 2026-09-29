package webrtc.telemetry

import webrtc.telemetry.CertificateAnalyzer.CertificateInfo
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CertificateAnalyzerTest {

    @Test fun `sha256 fingerprint uses uppercase colon-separated hex`() {
        val digest = CertificateAnalyzer.sha256Fingerprint("abc".toByteArray(Charsets.UTF_8))
        assertEquals("BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD", digest)
    }

    @Test fun `fingerprint normalization ignores case colons and spaces`() {
        assertEquals("AABBCC", CertificateAnalyzer.normalizeFingerprint("aa:bb: cc"))
    }

    @Test fun `sdp fingerprint extraction returns algorithm and value`() {
        val sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 AA:BB:CC\r\n"
        assertEquals(listOf("sha-256" to "AA:BB:CC"), CertificateAnalyzer.sdpFingerprints(listOf(sdp)))
    }

    @Test fun `binding mismatch is a finding and a match is silent`() {
        val matched = CertificateInfo("remote", "sha-256", "AA:BB", "CN=a", "CN=a", Instant.now().minusSeconds(60), Instant.now().plus(Duration.ofDays(90)), "EC", 256, true, "AA:BB", null)
        assertTrue(CertificateAnalyzer.analyze(listOf(matched), listOf("sha-256" to "AA:BB")).isEmpty())

        val mismatched = matched.copy(computedFingerprint = "CC:DD")
        val findings = CertificateAnalyzer.analyze(listOf(mismatched), listOf("sha-256" to "AA:BB"))
        assertTrue(findings.any { it.second && it.first.contains("does not match") })
    }

    @Test fun `expired and weak-key certificates are warnings`() {
        val expired = CertificateInfo("remote", "sha-256", "AA", "CN=a", "CN=a", Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600), "RSA", 1024, true, "AA", null)
        val findings = CertificateAnalyzer.analyze(listOf(expired), listOf("sha-256" to "AA"))
        assertTrue(findings.any { !it.second && it.first.contains("expired") })
        assertTrue(findings.any { !it.second && it.first.contains("weak RSA") })
    }

    @Test fun `unparseable certificate bytes are reported without throwing`() {
        val info = CertificateAnalyzer.parse("remote", "sha-256", "AA", "!!!not-base64!!!")
        assertNotNull(info.parseError)
        assertNotNull(CertificateAnalyzer.analyze(listOf(info), emptyList()))
        assertFalse(CertificateAnalyzer.analyze(listOf(info), emptyList()).any { it.second })
    }
}
