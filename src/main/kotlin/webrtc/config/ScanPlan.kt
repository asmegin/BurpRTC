package webrtc.config

import kotlinx.serialization.Serializable

enum class ScanModule(val id: String, val title: String) {
    PASSIVE("passive", "Passive SDP / ICE / DTLS / SRTP / codec review"),
    STATS("stats", "Capture live transport / media statistics"),
    ICE("ice", "Browser STUN / TURN gather (M6)"),
    SDP("sdp", "SDP / codec-parameter fuzzing (M3+)"),
    MUTATION("mutation", "SDP mutation rules (M3, next negotiation)"),
    DATA("data", "DataChannel payload fuzzing (M4)"),
    AUTHZ("authz", "HTTP authentication / IDOR (recent captured GET/HEAD requests)"),
    TLS("tls", "TLS versions / ciphers / certificates (SSLyze)"),
    STUN("stun", "Direct STUN binding / server discovery"),
    TURN("turn", "Direct TURN authentication / allocation / relay restrictions"),
    WS("ws", "WebSocket authentication / Origin / message probes"),
    SIP("sip", "SIP OPTIONS over UDP / TCP / TLS / WebSocket"),
    DTLS("dtls", "Direct DTLS handshake / certificate / cipher"),
    RTP("rtp", "RTP / RTCP packet probes (explicit media listener required)"),
    FUZZ("protocol-fuzz", "Bounded signaling / RTP packet mutations"),
    LOAD("protocol-load", "Bounded API / signaling / RTP load probes"),
    LOCAL_FLOOD("local-flood", "Local browser renegotiation / ICE-restart loop (T8)")
}

@Serializable
data class ScanPlan(val enabled: Set<String> = setOf("passive", "stats", "ice", "sdp", "data")) {
    fun includes(module: ScanModule) = module.id in enabled
}
