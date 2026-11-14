package webrtc.workflow

import burp.api.montoya.MontoyaApi
import webrtc.scope.ScopeGate
import java.net.URI

/**
 * T7 — passive signaling endpoint metadata. It reads what Burp has already
 * observed in Proxy history (no new request is made) and reports the HTTPS/WSS
 * origins used for signaling together with whether they sent
 * `Strict-Transport-Security`. Burp does not expose the negotiated TLS version
 * or cipher per request through this API, so those remain a review item to
 * confirm with an external scanner (see the External Tests tab).
 */
object SignalingMetadata {

    /** Raw observation from one proxied request/response pair. */
    data class Observation(val url: String, val secure: Boolean, val hsts: Boolean)

    /** Aggregated signaling origin. */
    data class Endpoint(val origin: String, val secure: Boolean, val hsts: Boolean, val requests: Int)

    fun classify(observations: List<Observation>): List<Endpoint> =
        observations.filter { it.url.startsWith("http://") || it.url.startsWith("https://") }
            .groupBy { origin(it.url) }
            .map { (origin, group) ->
                Endpoint(
                    origin = origin,
                    secure = group.any { it.secure },
                    hsts = group.any { it.hsts },
                    requests = group.size
                )
            }
            .sortedBy { it.origin }

    fun origin(url: String): String = runCatching {
        val uri = URI(url)
        val scheme = uri.scheme ?: return url
        val port = if (uri.port > 0) ":${uri.port}" else ""
        "$scheme://${uri.host}$port"
    }.getOrDefault(url)

    /** Review items only — none of these is a confirmed vulnerability. */
    fun findings(endpoints: List<Endpoint>): List<String> {
        val out = mutableListOf<String>()
        endpoints.filter { it.secure && !it.hsts }.forEach {
            out += "Signaling origin ${it.origin} served HTTPS but did not send Strict-Transport-Security; a downgrade is not blocked by the browser."
        }
        endpoints.filter { !it.secure }.forEach {
            out += "Signaling origin ${it.origin} was observed over plain HTTP; signaling (and any SDP/ICE credentials in it) is not protected in transit."
        }
        if (endpoints.any { it.secure })
            out += "Confirm the TLS version and cipher of the HTTPS/WSS signaling origins with the external testssl.sh recipe; Burp proxy history does not expose them here."
        return out
    }

    /**
     * Reads already-captured proxy history only. Hosts outside the allow-list are
     * ignored, and only the most recent [limit] responses are inspected.
     */
    fun collectFromProxy(api: MontoyaApi, hostAllowList: List<String>, limit: Int = 400): List<Endpoint> {
        val observations = runCatching {
            val history = api.proxy().history()
            val tail = if (history.size > limit) history.subList(history.size - limit, history.size) else history
            tail.mapNotNull { rr ->
                val url = runCatching { rr.request().url() }.getOrNull() ?: return@mapNotNull null
                val host = runCatching { URI(url).host }.getOrNull() ?: return@mapNotNull null
                if (hostAllowList.isNotEmpty() && !hostAllowList.any { it.equals("all", true) } &&
                    !ScopeGate.hostAllowed(host, hostAllowList)
                ) return@mapNotNull null
                val secure = runCatching { rr.request().httpService().secure() }.getOrDefault(url.startsWith("https://"))
                val hsts = runCatching { rr.hasResponse() && rr.response().hasHeader("Strict-Transport-Security") }
                    .getOrDefault(false)
                Observation(url, secure, hsts)
            }
        }.getOrDefault(emptyList())
        return classify(observations)
    }
}
