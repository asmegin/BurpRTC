package webrtc.workflow

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SignalingMetadataTest {

    @Test fun `origins are grouped with request counts and secure flag`() {
        val endpoints = SignalingMetadata.classify(listOf(
            SignalingMetadata.Observation("https://example.test/signal", true, true),
            SignalingMetadata.Observation("https://example.test/room", true, true),
            SignalingMetadata.Observation("http://legacy.test/ws", false, false),
            SignalingMetadata.Observation("not a url", false, false)
        ))
        assertEquals(listOf("http://legacy.test", "https://example.test"), endpoints.map { it.origin })
        assertEquals(2, endpoints.first { it.origin == "https://example.test" }.requests)
        assertTrue(endpoints.first { it.origin == "https://example.test" }.secure)
    }

    @Test fun `missing HSTS and plain HTTP are review items`() {
        val findings = SignalingMetadata.findings(listOf(
            SignalingMetadata.Endpoint("https://example.test", true, false, 1),
            SignalingMetadata.Endpoint("http://legacy.test", false, false, 1)
        ))
        assertTrue(findings.any { it.contains("Strict-Transport-Security") })
        assertTrue(findings.any { it.contains("plain HTTP") })
        assertTrue(findings.any { it.contains("testssl.sh") })
    }
}
