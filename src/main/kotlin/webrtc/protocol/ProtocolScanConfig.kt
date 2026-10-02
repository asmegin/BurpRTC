package webrtc.protocol

import kotlinx.serialization.Serializable
import webrtc.external.ExternalInputs
import java.net.URI

@Serializable
data class ProtocolScanConfig(
    val endpoints: List<String> = emptyList(),
    val turnUsername: String = "",
    val turnCredential: String = "",
    val relayPeer: String = "",
    val websocketOrigin: String = "",
    val websocketProtocol: String = "",
    val message: String = "",
    val mediaConfirmed: Boolean = false,
    val count: Int = 10,
    val intervalMs: Int = 250,
    val timeoutSeconds: Int = 120,
    val credentialConditions: List<CredentialCondition> = emptyList()
) {
    fun validate() {
        require(endpoints.size <= 20) { "Use at most 20 selected listeners" }
        require(credentialConditions.size <= 3 && credentialConditions.all { it.condition in setOf("expired", "revoked", "alternate-user") && it.basis.isNotBlank() }) { "Supplied credential conditions need a lifecycle/policy basis" }
        require(count in 1..50 && intervalMs in 100..5000) { "Use 1–50 messages, at least 100 ms apart" }
        require(timeoutSeconds in 15..300) { "Use a 15–300 second budget per listener" }
        require(message.toByteArray().size <= 4096) { "Signaling test message must be at most 4 KiB" }
        require(websocketOrigin.none { it == '\r' || it == '\n' }) { "Invalid Origin" }
        require(websocketProtocol.matches(Regex("[A-Za-z0-9._+-]*"))) { "Enter a single WebSocket subprotocol" }
        if (relayPeer.isNotBlank()) require(ProtocolTarget.parse(relayPeer).scheme == "udp") { "Relay peer must be udp://host:port" }
    }
}

@Serializable
data class CredentialCondition(val condition: String, val username: String, val password: String, val basis: String)

data class ProtocolTarget(val input: String, val scheme: String, val host: String, val port: Int, val transport: String, val scopeUrl: String) {
    companion object {
        fun parse(value: String): ProtocolTarget {
            val input = value.trim()
            ExternalInputs.parseIceUrl(input)?.let { ice ->
                require(ice.scheme in setOf("stun", "turn", "turns", "stuns")) { "Unsupported ICE scheme" }
                require(!(ice.scheme.endsWith("s") && input.endsWith("transport=udp", true))) { "Secure ICE scans use TCP TLS; enter dtls:// for a direct UDP handshake" }
                val host = ice.host.removeSurrounding("[", "]")
                val authority = if (host.contains(':')) "[$host]" else host
                require(ice.port in 1..65535) { "Invalid listener port" }
                return ProtocolTarget(input, ice.scheme, host, ice.port,
                    if (ice.scheme.endsWith('s')) "tls" else if (input.endsWith("transport=tcp", true)) "tcp" else "udp",
                    "${if (ice.scheme.endsWith('s')) "https" else "http"}://$authority:${ice.port}/")
            }
            val uri = runCatching { URI(input) }.getOrElse { throw IllegalArgumentException("Invalid listener URL") }
            val scheme = uri.scheme?.lowercase().orEmpty()
            require(scheme in setOf("http", "https", "ws", "wss", "sip", "sips", "dtls", "rtp", "rtcp", "udp")) { "Use a STUN/TURN URI or http(s)://, ws(s)://, sip(s)://, dtls://, rtp:// or rtcp:// listener" }
            require(uri.host != null && uri.userInfo == null && uri.fragment == null) { "Enter a listener URL without userinfo or a fragment" }
            val port = if (uri.port >= 0) uri.port else when (scheme) { "http", "ws" -> 80; "https", "wss" -> 443; "sip" -> 5060; "sips" -> 5061; else -> 0 }
            require(port in 1..65535) { "Specify a listener port (1–65535)" }
            if (scheme !in setOf("http", "https", "ws", "wss")) require(uri.rawPath in listOf(null, "", "/") && (uri.rawQuery == null || (scheme == "sip" && uri.rawQuery == "transport=tcp"))) { "This listener cannot have a path/query" }
            val host = uri.host.removeSurrounding("[", "]")
            val authority = if (host.contains(':')) "[$host]" else host
            val secure = scheme in setOf("https", "wss", "sips", "dtls")
            val transport = when { scheme in setOf("dtls", "rtp", "rtcp", "udp") -> "udp"; scheme == "sip" && uri.rawQuery != "transport=tcp" -> "udp"; secure -> "tls"; else -> "tcp" }
            val suffix = if (scheme in setOf("http", "https", "ws", "wss")) uri.rawPath.orEmpty().ifEmpty { "/" } + (uri.rawQuery?.let { "?$it" }.orEmpty()) else "/"
            return ProtocolTarget(input, scheme, host, port, transport, "${if (secure) "https" else "http"}://$authority:$port$suffix")
        }
    }
}
