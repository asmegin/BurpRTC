package webrtc.tls

import kotlinx.serialization.Serializable
import webrtc.external.ExternalInputs
import java.net.URI

@Serializable
data class TlsScanConfig(
    val pythonExecutable: String = "python",
    val endpoint: String = "",
    val timeoutSeconds: Int = 180,
    val vulnerabilityChecks: Boolean = false,
    // Retained for old project JSON. Scan All now uses ScanPlan's TLS selection.
    val includeInRunAll: Boolean = false,
    /** "builtin" runs the JVM scanner inside Burp; "sslyze" uses the optional managed Python environment. */
    val engine: String = "builtin"
) {
    fun validate() {
        require(engine in setOf("builtin", "sslyze")) { "TLS engine must be built-in or SSLyze" }
        require(pythonExecutable.isNotBlank() && pythonExecutable.none { it == '\u0000' || it == '\n' || it == '\r' }) { "Select a Python 3.10+ executable" }
        require(timeoutSeconds in 15..300) { "Use a 15–300 second scan timeout" }
    }
}

/** A TLS listener, never an ICE candidate/allocated relay address or a DTLS UDP endpoint. */
data class TlsTarget(val input: String, val host: String, val port: Int, val scopeUrl: String) {
    companion object {
        fun parse(value: String): TlsTarget {
            val input = value.trim()
            val ice = ExternalInputs.parseIceUrl(input)
            if (ice != null) {
                require(ice.scheme == "turns" && !input.endsWith("transport=udp", ignoreCase = true) && ice.port in 1..65535) {
                    "TLS runner supports turns: listeners over TCP. Plain TURN/STUN and DTLS over UDP need their own protocol tests."
                }
                val authority = if (ice.host.contains(':')) "[${ice.host.removeSurrounding("[", "]")}]" else ice.host
                return TlsTarget(input, ice.host.removeSurrounding("[", "]"), ice.port, "https://$authority:${ice.port}/")
            }
            val uri = runCatching { URI(input) }.getOrNull()
                ?: throw IllegalArgumentException("Use https://host:port/path, wss://host:port/path, tls://host:port or turns:host:port?transport=tcp")
            val scheme = uri.scheme?.lowercase()
            require(scheme in setOf("https", "wss", "tls") && uri.host != null && uri.userInfo == null && uri.fragment == null) {
                "Use a TLS endpoint URL without credentials or a fragment; UDP DTLS is not supported by this runner"
            }
            val port = if (uri.port == -1) 443 else uri.port
            require(port in 1..65535) { "Invalid TLS port" }
            require(scheme != "tls" || (uri.rawPath in listOf(null, "", "/") && uri.rawQuery == null && uri.port != -1)) {
                "tls:// requires an explicit port and no path/query"
            }
            val host = uri.host.removeSurrounding("[", "]")
            val scope = if (scheme == "https") input else
                "https://${uri.rawAuthority}${uri.rawPath.orEmpty().ifEmpty { "/" }}${uri.rawQuery?.let { "?$it" }.orEmpty()}"
            return TlsTarget(input, host, port, scope)
        }
    }
}
