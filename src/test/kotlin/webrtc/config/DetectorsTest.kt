package webrtc.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DetectorsTest {

    @Test fun `strong transport is not flagged`() {
        val findings = Detectors.analyzeTransportSecurity(
            "dtls=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 srtp=AEAD_AES_128_GCM tls=1.3"
        )
        assertTrue(findings.isEmpty(), "unexpected findings: $findings")
    }

    @Test fun `standard SHA1 SRTP auth is not treated as weak`() {
        // HMAC-SHA1 SRTP auth tags are normal WebRTC, not a finding.
        val findings = Detectors.analyzeTransportSecurity(
            "dtls=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 srtp=AES_CM_128_HMAC_SHA1_80 tls=1.2"
        )
        assertTrue(findings.isEmpty(), "unexpected findings: $findings")
    }

    @Test fun `unknown crypto is not weak but weak crypto is flagged`() {
        // Missing/unknown stats are not evidence of missing encryption (0.8.1).
        assertTrue(Detectors.analyzeTransportSecurity("dtls=? srtp=? tls=?").isEmpty())
        assertTrue(Detectors.analyzeTransportSecurity("dtls=TLS_RSA_WITH_RC4_128_SHA srtp=AES_CM_128_HMAC_SHA1_80 tls=1.2")
            .any { it.contains("Weak DTLS", ignoreCase = true) })
        assertTrue(Detectors.analyzeTransportSecurity("dtls=x srtp=NULL_NULL tls=1.2")
            .any { it.contains("NULL SRTP", ignoreCase = true) })
        assertTrue(Detectors.analyzeTransportSecurity("dtls=x srtp=AEAD_AES_128_GCM tls=1.0")
            .any { it.contains("Legacy", ignoreCase = true) })
    }

    @Test fun `SDES and DTLS fingerprint detection`() {
        val sdesSdp = "v=0\r\nm=audio 9 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc\r\n"
        val dtlsSdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 AA:BB\r\na=rtpmap:111 opus/48000\r\n"
        assertTrue(Detectors.usesSdesKeys(sdesSdp))
        assertFalse(Detectors.usesSdesKeys(dtlsSdp))
        assertTrue(Detectors.hasDtlsFingerprint(dtlsSdp))
        assertFalse(Detectors.hasDtlsFingerprint(sdesSdp))
        assertTrue(Detectors.hasMedia(sdesSdp))
    }

    @Test fun `codec enumeration extracts distinct names`() {
        val sdp = "m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n" +
            "a=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\n" +
            "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:96 VP8/90000\r\n"
        assertEquals(listOf("opus", "PCMU", "VP8"), Detectors.enumerateCodecs(sdp))
    }

    @Test fun `candidate parsing and IP privacy classification`() {
        val host = Detectors.parseCandidate("candidate:1 1 udp 2122260223 192.168.1.5 54400 typ host generation 0")
        assertNotNull(host)
        assertEquals("192.168.1.5", host.address)
        assertEquals("host", host.type)
        assertEquals("udp", host.protocol)
        assertTrue(IpAddresses.isPrivate(host.address))

        val srflx = Detectors.parseCandidate("candidate:2 1 UDP 1686052863 203.0.113.9 54400 typ srflx raddr 10.0.0.7 rport 54400")
        assertEquals("srflx", srflx!!.type)
        assertEquals("10.0.0.7", srflx.relatedAddress)
        assertTrue(Detectors.isPublicAddress("203.0.113.9"))
        assertFalse(Detectors.isPublicAddress("192.168.1.5"))
        assertFalse(Detectors.isPublicAddress("10.0.0.7"))
        assertFalse(Detectors.isPublicAddress("fe80::1"))
        assertFalse(Detectors.isPublicAddress("abc.local"))
        assertNull(Detectors.parseCandidate("not a candidate"))

        val tcp6 = Detectors.parseCandidate("candidate:3 1 tcp 1518280447 [2001:db8::1] 9 typ host tcptype active")
        assertNotNull(tcp6)
        assertTrue(Detectors.isIpv6(tcp6.address))
        assertEquals("tcp", tcp6.protocol)
        assertTrue(Detectors.isMdns("a1b2.local"))
        assertFalse(Detectors.isMdns("192.168.1.5"))
    }

    @Test fun `ICE credential hygiene flags short and reused credentials`() {
        assertNotNull(Detectors.auditIceCredential(Detectors.IceCredential("ab", "x".repeat(24))))
        assertNotNull(Detectors.auditIceCredential(Detectors.IceCredential("abcd", "short")))
        assertNull(Detectors.auditIceCredential(Detectors.IceCredential("abcd", "0123456789012345678901")))
        val reused = listOf(
            listOf(Detectors.IceCredential("aaaa", "p".repeat(24))),
            listOf(Detectors.IceCredential("aaaa", "p".repeat(24)))
        )
        assertNull(Detectors.iceCredentialReuse(reused))
        assertNotNull(Detectors.iceCredentialReuse(reused, deliberateRestart = true))
        val rotated = listOf(
            listOf(Detectors.IceCredential("aaaa", "p".repeat(24))),
            listOf(Detectors.IceCredential("bbbb", "q".repeat(24)))
        )
        assertNull(Detectors.iceCredentialReuse(rotated))
    }

    @Test fun `SDP attribute audit flags weak fingerprint and missing rtcp-mux`() {
        val weak = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-1 AA:BB\r\na=rtpmap:111 opus/48000/2\r\n"
        val findings = Detectors.auditSdpAttributes(weak)
        assertTrue(findings.any { it.finding && it.text.contains("sha-1") })
        assertTrue(findings.any { it.text.contains("rtcp-mux") })
        val strong = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 AA:BB\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\n"
        assertFalse(Detectors.auditSdpAttributes(strong).any { it.finding })
    }

    @Test fun `codec details include fmtp and setup roles`() {
        val sdp = "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\n" +
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\n" +
            "a=setup:actpass\r\n"
        val details = Detectors.codecDetails(sdp)
        assertEquals(2, details.size)
        assertTrue(details.any { it.name == "H264" && it.fmtp?.contains("profile-level-id") == true })
        assertTrue(details.any { it.name == "opus" && it.channels == "2" })
        assertEquals(listOf("actpass"), Detectors.setupRoles(sdp))
    }

    @Test fun `guessable identifiers heuristic`() {
        assertNotNull(Detectors.guessableIdentifiers(listOf("1001", "1002")))
        assertNotNull(Detectors.guessableIdentifiers(listOf("500", "501", "503")))
        assertNull(Detectors.guessableIdentifiers(listOf("a1b2c3d4e5", "f6g7h8i9j0")))
        assertNull(Detectors.guessableIdentifiers(listOf("1001"))) // needs at least two
        assertNull(Detectors.guessableIdentifiers(emptyList()))
    }
}
