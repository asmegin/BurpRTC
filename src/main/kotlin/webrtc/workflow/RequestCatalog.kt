package webrtc.workflow

import burp.api.montoya.http.message.requests.HttpRequest
import java.net.URI

/** Recent browser GET/HEAD requests for opt-out automatic auth checks; held only in memory. */
class RequestCatalog {
    private data class Entry(val request: HttpRequest, val json: Boolean)
    private val entries = LinkedHashMap<String, Entry>()

    @Synchronized fun observe(request: HttpRequest, contentType: String, status: Int) {
        if (request.method() !in setOf("GET", "HEAD") || status !in 200..299) return
        if (!contentType.contains("json", true) && !contentType.contains("text/html", true)) return
        if (Regex("(?i)(logout|signout|delete|remove|revoke|unsubscribe)").containsMatchIn(request.path())) return
        entries[request.url()] = Entry(request, contentType.contains("json", true))
        while (entries.size > 50) entries.remove(entries.keys.first())
    }

    @Synchronized fun forPage(page: String, limit: Int): List<HttpRequest> {
        val origin = origin(page)
        return entries.values.toList().asReversed().filter { origin(it.request.url()) == origin }
            .sortedByDescending { it.json }.take(limit).map { it.request }
    }

    @Synchronized fun recent(limit: Int = 5): List<HttpRequest> = entries.values.toList().asReversed()
        .sortedByDescending { it.json }.take(limit.coerceIn(0, 5)).map { it.request }

    companion object {
        fun origin(value: String): String {
            val uri = URI(value)
            require(uri.scheme in listOf("http", "https") && uri.host != null && uri.userInfo == null) { "Enter a full http:// or https:// page URL" }
            return "${uri.scheme}://${uri.host}${if (uri.port >= 0) ":${uri.port}" else ""}/"
        }
    }
}
