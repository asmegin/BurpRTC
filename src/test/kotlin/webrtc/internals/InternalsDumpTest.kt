package webrtc.internals

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InternalsDumpTest {

    @Test fun `parses a JSON dump array with candidates, SDP, ciphers and codecs`() {
        val dump = InternalsDump.parse(
            """
            [
              {"type":"icecandidate","value":"candidate:1 1 UDP 2122260223 192.168.1.5 54400 typ host"},
              {"type":"setLocalDescription","value":"v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=fingerprint:sha-256 AA\r\n"},
              {"type":"stats","dtlsCipher":"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","srtpCipher":"AEAD_AES_128_GCM","tlsVersion":"TLS 1.3","codec":"VP8"}
            ]
            """.trimIndent()
        )

        assertEquals(1, dump.candidates.size)
        assertTrue("192.168.1.5" in dump.addresses, "addresses=${dump.addresses}")
        assertTrue("opus" in dump.codecs, "codecs=${dump.codecs}")
        assertTrue("VP8" in dump.codecs, "codecs=${dump.codecs}")
        assertTrue("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" in dump.dtlsCiphers)
        assertTrue("AEAD_AES_128_GCM" in dump.srtpCiphers)
        assertTrue("TLS 1.3" in dump.tlsVersions)
        assertEquals(1, dump.sdpBlocks)
        assertFalse(dump.isEmpty)
    }

    @Test fun `parses a plain-text copy of the page`() {
        val dump = InternalsDump.parse(
            """
            rtpCipherSuite: SRTP_AES128_CM_SHA1_80
            candidate:1 1 UDP 2122260223 10.0.0.7 54400 typ host
            candidate:2 1 UDP 1686052863 203.0.113.9 55000 typ srflx raddr 10.0.0.7 rport 54400
            a=rtpmap:96 VP8/90000
            """.trimIndent()
        )

        assertEquals(2, dump.candidates.size)
        assertTrue("10.0.0.7" in dump.addresses, "addresses=${dump.addresses}")
        assertTrue("203.0.113.9" in dump.addresses, "addresses=${dump.addresses}")
        assertTrue("VP8" in dump.codecs, "codecs=${dump.codecs}")
        assertTrue("SRTP_AES128_CM_SHA1_80" in dump.srtpCiphers, "srtp=${dump.srtpCiphers}")
    }

    @Test fun `detects the user agent and mDNS hostnames`() {
        val dump = InternalsDump.parse(
            """{"userAgent":"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120","candidate":"candidate:1 1 UDP 1 a1b2c3d4-1234-5678-9abc-def012345678.local 54400 typ host"}"""
        )
        assertTrue(dump.userAgent!!.contains("Chrome"))
        assertTrue("a1b2c3d4-1234-5678-9abc-def012345678.local" in dump.mdnsNames, "mdns=${dump.mdnsNames}")
    }

    @Test fun `unrecognised input is reported as empty`() {
        assertTrue(InternalsDump.parse("").isEmpty)
        assertTrue(InternalsDump.parse("hello world, not a dump").isEmpty)
    }
}
