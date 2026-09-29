package webrtc.internals

import webrtc.telemetry.TelemetryEvent
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InternalsComparatorTest {

    private fun ev(type: String, raw: String) =
        TelemetryEvent(1, "00:00:00.000", type, "https://example.test", "", false, type, raw)

    private val extIce = ev("ice", """{"type":"ice","candidate":"candidate:1 1 UDP 1 203.0.113.9 54400 typ host"}""")
    private val extSdp = ev(
        "sdp-remote",
        """{"type":"sdp-remote","sdp":"v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\n"}"""
    )
    private val extCrypto = ev(
        "crypto",
        """{"type":"crypto","detail":"dtls=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 srtp=AEAD_AES_128_GCM tls=1.3"}"""
    )

    @Test fun `matching dump and telemetry report only ok lines`() {
        val dump = InternalsDump(
            candidates = setOf("candidate:1 1 UDP 1 203.0.113.9 54400 typ host"),
            addresses = setOf("203.0.113.9"),
            codecs = setOf("opus"),
            dtlsCiphers = setOf("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
            srtpCiphers = setOf("AEAD_AES_128_GCM"),
            tlsVersions = setOf("TLS 1.3")
        )
        val lines = InternalsComparator.compare(dump, listOf(extIce, extSdp, extCrypto))
        assertTrue(lines.any { it.level == InternalsComparator.Level.OK && it.text.contains("candidate addresses match") }, "$lines")
        assertTrue(lines.any { it.level == InternalsComparator.Level.OK && it.text.contains("Codec list matches") }, "$lines")
        assertTrue(lines.any { it.level == InternalsComparator.Level.OK && it.text.contains("no weak cipher was identified") }, "$lines")
        assertFalse(lines.any { it.level == InternalsComparator.Level.FINDING }, "$lines")
    }

    @Test fun `weak cipher is a finding and a local private address is informational`() {
        val dump = InternalsDump(
            candidates = setOf("candidate:1 1 UDP 1 192.168.1.5 54400 typ host"),
            addresses = setOf("192.168.1.5"),
            dtlsCiphers = setOf("TLS_RSA_WITH_RC4_128_SHA"),
            srtpCiphers = setOf("NULL_NULL")
        )
        val lines = InternalsComparator.compare(dump, listOf(extIce, extCrypto))
        assertTrue(lines.any { it.level == InternalsComparator.Level.FINDING && it.text.contains("Weak DTLS") }, "$lines")
        assertTrue(lines.any { it.level == InternalsComparator.Level.FINDING && it.text.contains("NULL SRTP") }, "$lines")
        // A local dump's private address is informational, not proof of disclosure.
        assertTrue(lines.any { it.level == InternalsComparator.Level.INFO && it.text.contains("private IP address") }, "$lines")
    }

    @Test fun `addresses only in the dump are warned`() {
        val dump = InternalsDump(
            candidates = setOf("candidate:2 1 UDP 1 10.0.0.7 55000 typ host"),
            addresses = setOf("10.0.0.7"),
            codecs = setOf("opus", "H264")
        )
        val lines = InternalsComparator.compare(dump, listOf(extIce, extSdp))
        assertTrue(lines.any { it.level == InternalsComparator.Level.WARN && it.text.contains("10.0.0.7") }, "$lines")
        assertTrue(lines.any { it.level == InternalsComparator.Level.WARN && it.text.contains("Codec", ignoreCase = true) }, "$lines")
    }

    @Test fun `empty dump is warned about, not treated as agreement`() {
        val lines = InternalsComparator.compare(InternalsDump(), listOf(extIce))
        assertTrue(lines.any { it.level == InternalsComparator.Level.WARN && it.text.contains("did not contain") }, "$lines")
    }

    @Test fun `comparison lines round-trip through storage`() {
        val original = listOf(
            InternalsComparator.Line(InternalsComparator.Level.FINDING, "weak cipher"),
            InternalsComparator.Line(InternalsComparator.Level.OK, "all good")
        )
        val decoded = InternalsComparator.decodeLines(InternalsComparator.encodeLines(original))
        assertTrue(decoded == original, "$decoded")
    }
}
