package webrtc.config

import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
data class DataChannelFuzzConfig(
    val mode: String = "text",
    val payload: String = "WebRTC test",
    val count: Int = 1,
    val intervalMs: Int = 250,
    val maxBytes: Int = 4096,
    val stopOnError: Boolean = true
) {
    fun validate() {
        require(mode in listOf("text", "hex", "json", "boundary")) { "Unknown payload mode" }
        require(count in 1..50 && intervalMs in 100..1000) { "Use 1-50 messages and a 100-1000 ms interval" }
        require(maxBytes in 1..65536 && count.toLong() * maxBytes <= 1048576) { "Limit each message to 65,536 bytes and each run to 1 MiB" }
        if (mode == "text") require(payload.toByteArray(Charsets.UTF_8).size <= maxBytes) { "Text exceeds the payload byte limit" }
        if (mode == "hex") {
            val hex = payload.replace(Regex("\\s"), "")
            require(hex.length % 2 == 0 && hex.matches(Regex("[0-9a-fA-F]*"))) { "Binary payload must contain pairs of hexadecimal digits" }
            require(hex.length / 2 <= maxBytes) { "Binary payload exceeds the byte limit" }
        }
    }
}

@Serializable
data class SdpFuzzConfig(
    val descriptionType: String = "offer",
    val maxCases: Int = 300
) {
    fun validate() {
        require(descriptionType in listOf("offer", "answer")) { "Description type must be offer or answer" }
        require(maxCases in 1..500) { "Run between 1 and 500 fuzz cases" }
    }
}

@Serializable
data class IceProbeConfig(
    val url: String = "",
    val username: String = "",
    val credential: String = "",
    val policy: String = "all",
    val timeoutSeconds: Int = 10,
    val useObservedCredentials: Boolean = false
) {
    fun validate(): IceEndpoint? {
        require(policy in listOf("all", "relay")) { "ICE policy must be all or relay" }
        require(timeoutSeconds in 3..30) { "ICE timeout must be 3-30 seconds" }
        val endpoint = url.takeIf { it.isNotBlank() }?.let { IceEndpoint.parse(it) }
        require(policy != "relay" || endpoint?.turn == true) { "Relay-only gathering requires a TURN server" }
        require(endpoint?.turn != true || useObservedCredentials || (username.isNotBlank() && credential.isNotEmpty())) { "TURN requires a username and credential" }
        return endpoint
    }
}

/**
 * T8 — bounded, opt-in local renegotiation / ICE-restart loop. It drives only the
 * page's own `createOffer`/`setLocalDescription`; nothing is sent to the signaling
 * server. Off by default and never started by Run All unless [confirm] is set.
 */
@Serializable
data class SignalingFloodConfig(
    val confirm: Boolean = false,
    val count: Int = 5,
    val intervalMs: Int = 1000
) {
    fun validate() {
        require(confirm) { "Signaling/ICE-restart flood is opt-in; tick the confirmation before running" }
        require(count in 1..20) { "Use 1-20 renegotiations" }
        require(intervalMs in 500..5000) { "Use a 500-5000 ms interval" }
    }
}

/** HTTP(S) scope URL represents the ICE host and port; no HTTP request is made. */
data class IceEndpoint(val scopeUrl: String, val turn: Boolean) {
    companion object {
        fun parse(value: String): IceEndpoint {
            val match = Regex("^(stun|stuns|turn|turns):(\\[[0-9a-fA-F:.]+]|[a-zA-Z0-9._-]+)(?::([0-9]+))?(?:\\?transport=(udp|tcp))?$", RegexOption.IGNORE_CASE)
                .matchEntire(value) ?: throw IllegalArgumentException("Use stun:host:port, turn:host:port?transport=udp|tcp, or turns:host:port?transport=tcp")
            val scheme = match.groupValues[1].lowercase()
            val turn = scheme.startsWith("turn")
            require(turn || match.groupValues[4].isEmpty()) { "STUN URIs do not accept a transport query" }
            val secure = scheme.endsWith('s')
            val port = match.groupValues[3].ifEmpty { if (secure) "5349" else "3478" }.toIntOrNull()
            require(port != null && port in 1..65535) { "Invalid ICE server port" }
            val url = "${if (secure) "https" else "http"}://${match.groupValues[2]}:$port/"
            require(runCatching { URI(url).host }.getOrNull() != null) { "Invalid ICE server host" }
            return IceEndpoint(url, turn)
        }
    }
}
