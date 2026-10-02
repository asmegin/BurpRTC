package webrtc.assessment

import webrtc.config.ConfigStore
import webrtc.scope.ScopeGate
import java.net.URI

/** Hostnames and concrete destination IPs are independent scope entries. No DNS inheritance. */
class NetworkAuthorization(private val config: ConfigStore, private val inScope: (String) -> Boolean) {
    fun allows(url: String): Boolean = runCatching {
        val uri = URI(url); val cfg = config.config
        cfg.injectionEnabled && uri.scheme in setOf("http", "https") && uri.host != null && uri.userInfo == null &&
            ScopeGate.hostAllowed(uri.host.removeSurrounding("[", "]"), cfg.hostAllowList) && inScope(url)
    }.getOrDefault(false)
    fun allowsLeg(url: String, address: String, port: Int): Boolean = runCatching {
        val uri = URI(url)
        val expectedPort = if (uri.port >= 0) uri.port else if (uri.scheme == "https") 443 else 80
        val literal = webrtc.config.IpAddresses.literal(address) ?: return false
        val authority = if (literal.address.size == 16) "[$address]" else address
        val ipUrl = "${uri.scheme}://$authority:$port${uri.rawPath.orEmpty().ifBlank { "/" }}${uri.rawQuery?.let { "?$it" }.orEmpty()}"
        port == expectedPort && allows(url) && allows(ipUrl)
    }.getOrDefault(false)
}
