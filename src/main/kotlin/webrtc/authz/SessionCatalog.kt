package webrtc.authz

import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.json.*
import webrtc.config.ConfigStore
import webrtc.config.IdentityProfile
import webrtc.scope.ScopeGate
import java.net.URI
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

data class CapturedSession(
    val id: Long, val label: String, val origin: String, val identity: IdentityProfile,
    val lastSeen: Instant, val observations: Int, val source: String,
    val requests: List<HttpRequest> = emptyList(), val roomUrls: List<String> = emptyList(),
    val xmpp: List<String> = emptyList(), val observedTokens: List<String> = emptyList()
) {
    fun claims(): List<JsonObject> = (AuthTokens.values(identity) + observedTokens).mapNotNull(AuthTokens::jwtClaims).distinct()
    fun summary(): String = claims().joinToString("; ") { c ->
        val user = (c["context"] as? JsonObject)?.get("user") as? JsonObject
        (listOf("sub", "room", "iss").mapNotNull { key -> c[key]?.let { "$key=${(it as? JsonPrimitive)?.content ?: it}" } } +
            listOf("name", "email", "moderator").mapNotNull { key -> user?.get(key)?.let { "$key=${(it as? JsonPrimitive)?.content ?: it}" } }).joinToString(", ")
    }.ifBlank { "Opaque credentials; identity needs confirmation" }
    fun state(): String {
        val times = claims().mapNotNull { (it["exp"] as? JsonPrimitive)?.longOrNull }
        val starts = claims().mapNotNull { (it["nbf"] as? JsonPrimitive)?.longOrNull }
        return when { times.any { it <= Instant.now().epochSecond } -> "JWT expired (unverified)"
            starts.any { it > Instant.now().epochSecond } -> "JWT not yet valid (unverified)"
            !AuthTokens.hasCredentials(identity) -> "Fresh protocol login required"
            xmpp.isNotEmpty() -> "XMPP observed"
            times.isNotEmpty() -> "JWT expiry in future (unverified)"
            else -> "Recently observed" }
    }
    fun details(): String = buildString {
        appendLine("$label\nRole: ${identity.role.ifBlank { "not set (set Customer / Advisor to enable access expectations)" }}\nOrigin: $origin\nLast seen: $lastSeen\nSource: $source\nState: ${state()}")
        appendLine("JWT claims are decoded without signature verification; a captured token is not a confirmed principal.\n")
        identity.headers.forEach { (k, v) -> appendLine("Header $k: $v") }
        identity.queryTokens.forEach { (k, v) -> appendLine("URL $k: $v") }
        identity.bodyTokens.forEach { (k, v) -> appendLine("Body $k: $v") }
        observedTokens.forEach { appendLine("Observed XMPP token: $it (transport binding requires review)") }
        claims().forEach { appendLine("\nJWT claims: $it") }
        roomUrls.forEach { appendLine("\nRoom URL: $it") }
        xmpp.forEach { appendLine("\nXMPP: $it") }
        appendLine("\n${requests.size} captured read request(s)")
    }
}

/** Passive, scoped, memory-only credential bundles. Extension replays never enter this catalog. */
class SessionCatalog(private val config: ConfigStore, private val scope: ScopeGate) {
    private val entries = LinkedHashMap<String, CapturedSession>()
    private val selected = linkedSetOf<Long>()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()
    private var nextId = 0L
    fun onChange(listener: () -> Unit) { listeners += listener }
    private fun changed() = listeners.forEach { runCatching(it) }
    private fun allowed(url: String): Boolean = runCatching {
        ScopeGate.hostAllowed(URI(url).host, config.config.hostAllowList) && scope.inScope(url)
    }.getOrDefault(false)
    @Synchronized fun snapshot() = entries.values.toList().asReversed()
    @Synchronized fun selection() = entries.values.filter { it.id in selected }
    @Synchronized fun isSelected(id: Long) = id in selected
    @Synchronized fun select(id: Long, value: Boolean) { if (value) selected += id else selected -= id; changed() }
    @Synchronized fun rename(id: Long, label: String) {
        val e = entries.entries.firstOrNull { it.value.id == id } ?: return
        if (label.isBlank()) return
        e.setValue(e.value.copy(label = label.trim(), identity = e.value.identity.copy(name = label.trim(), role = e.value.identity.role)))
        changed()
    }
    /** Business role used for access expectations: guest, customer, advisor, admin or blank. */
    @Synchronized fun setRole(id: Long, role: String) {
        val e = entries.entries.firstOrNull { it.value.id == id } ?: return
        val value = role.trim().lowercase().takeIf { it.isEmpty() || webrtc.config.Roles.rank(it) != null } ?: return
        e.setValue(e.value.copy(identity = e.value.identity.copy(role = value)))
        changed()
    }
    @Synchronized fun byId(id: Long?): CapturedSession? = entries.values.firstOrNull { it.id == id }
    @Synchronized fun clear() { entries.clear(); selected.clear(); changed() }
    @Synchronized fun observe(req: HttpRequest, contentType: String = "", status: Int = 0, source: String = "HTTP"): Long? {
        if (!allowed(req.url()) || req.bodyToString().length > 262144) return null
        val identity = AuthTokens.capture(req)
        if (!AuthTokens.hasCredentials(identity)) return null
        val origin = AuthTokens.origin(req.url()) ?: return null
        // Length framing makes bundle equality independent of delimiters inside secrets.
        val key = listOf(origin) + (identity.headers.toSortedMap().flatMap { listOf("header:${it.key}", it.value) } +
            identity.queryTokens.toSortedMap().flatMap { listOf("query:${it.key}", it.value) } + identity.bodyTokens.toSortedMap().flatMap { listOf("body:${it.key}", it.value) })
        val bundle = key.joinToString("") { "${it.length}:$it" }
        val previous = entries[bundle]
        val id = previous?.id ?: ++nextId
        val reads = previous?.requests.orEmpty().toMutableList()
        if (eligibleRead(req, contentType, status)) {
            reads.removeAll { it.url() == req.url() && it.method() == req.method() }
            reads.add(0, req)
        }
        val rooms = previous?.roomUrls.orEmpty().toMutableList()
        val query = AuthTokens.pairs(req.path().substringAfter('?', "")).toMap()
        // Page URLs with jwt are useful fresh-login targets. Handshakes provide explicit room + token.
        if (contentType.contains("html", true) && req.method() == "GET" && query.containsKey("jwt")) rooms += req.url()
        if (req.path().substringBefore('?').endsWith("/xmpp-websocket") && query["room"]?.isNotBlank() == true) {
            val room = query.getValue("room")
            if (room.matches(Regex("[A-Za-z0-9_.~-]+"))) {
                val token = query["token"] ?: query["jwt"]
                val uri = URI(req.url())
                val scheme = if (uri.scheme in setOf("wss", "https")) "https" else "http"
                val prefix = uri.rawPath.substringBeforeLast("/xmpp-websocket")
                if (token != null) rooms += "$scheme://${uri.rawAuthority}" +
                    AuthTokens.queryPath("$prefix/$room", mapOf("jwt" to token), false)
            }
        }
        val label = previous?.label ?: "Session $id"
        entries[bundle] = CapturedSession(id, label, origin, identity.copy(name = label, role = previous?.identity?.role.orEmpty()), Instant.now(),
            (previous?.observations ?: 0) + 1, source, reads.take(5), rooms.distinct().takeLast(5), previous?.xmpp.orEmpty(), previous?.observedTokens.orEmpty())
        while (entries.size > 100) { selected.remove(entries.values.first().id); entries.remove(entries.keys.first()) }
        changed()
        return id
    }
    @Synchronized fun observeXmpp(id: Long?, url: String, payload: String, connection: String = "") {
        if (!allowed(url) || payload.length > 262144 ||
            !Regex("<(?:[\\w-]+:)?(?:auth|open|presence|body)\\b").containsMatchIn(payload)) return
        var entry = entries.entries.firstOrNull { it.value.id == id }
        if (entry == null) {
            // SASL credentials observed without an HTTP token have an unknown binding.
            // Keep them visible, but never invent a header/query location for replays.
            if (!Regex("<(?:[\\w-]+:)?auth\\b").containsMatchIn(payload)) return
            val origin = AuthTokens.origin(url) ?: return
            val key = "xmpp:$url:$connection"
            val previous = entries[key]
            val sessionId = previous?.id ?: ++nextId
            entries[key] = previous ?: CapturedSession(sessionId, "Session $sessionId", origin,
                IdentityProfile("Session $sessionId", origins = listOf(origin)), Instant.now(), 1, "XMPP SASL")
            entry = entries.entries.first { it.key == key }
        }
        val jwtPattern = Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
        val auth = Regex("<(?:[\\w-]+:)?auth\\b[^>]*>([^<]*)</").find(payload)?.groupValues?.get(1).orEmpty()
        val decoded = runCatching { String(java.util.Base64.getDecoder().decode(auth), Charsets.UTF_8) }.getOrDefault("")
        val tokens = jwtPattern.findAll(payload + "\n" + decoded).map { it.value }.filter { AuthTokens.jwtClaims(it) != null }.toList()
        entry.setValue(entry.value.copy(lastSeen = Instant.now(), xmpp = (entry.value.xmpp + payload).distinct().takeLast(8),
            observedTokens = (entry.value.observedTokens + tokens).distinct().takeLast(8)))
        while (entries.size > 100) { selected.remove(entries.values.first().id); entries.remove(entries.keys.first()) }
        changed()
    }
    companion object {
        fun eligibleRead(req: HttpRequest, contentType: String, status: Int) = req.method() in setOf("GET", "HEAD") &&
            status in 200..299 && contentType.contains("json", true) && !req.hasHeader("Upgrade") &&
            !Regex("(?i)(logout|signout|delete|remove|revoke|unsubscribe|http-bind|xmpp-websocket)").containsMatchIn(req.path())

        /** Fresh browser navigation; never transplant XMPP sid/rid or alter a live connection. */
        fun roomSwaps(sessions: List<CapturedSession>): String = buildString {
            appendLine("Open each URL in a fresh, separate browser profile routed through Burp.\nVerify actual room admission and intended guest/moderator policy. HTTP 200 is not room admission.\n")
            fun path(uri: URI) = uri.rawPath + "?" + uri.rawQuery.orEmpty().split('&')
                .filterNot { AuthTokens.decode(it.substringBefore('=')) in setOf("sid", "rid") }.joinToString("&")
            for (owner in sessions) for (url in owner.roomUrls) {
                val uri = URI(url)
                appendLine("${owner.label}'s baseline room login:\n$url\n")
                appendLine("${owner.label}'s room without a URL token:")
                appendLine("${uri.scheme}://${uri.rawAuthority}${AuthTokens.queryPath(path(uri), emptyMap())}\n")
            }
            var count = 0
            for (owner in sessions) for (donor in sessions) {
                if (owner.id == donor.id || owner.origin != donor.origin) continue
                val jwt = (AuthTokens.values(donor.identity) + donor.observedTokens).firstOrNull { AuthTokens.jwtClaims(it) != null } ?: continue
                if (jwt in AuthTokens.values(owner.identity) + owner.observedTokens) continue
                for (url in owner.roomUrls) {
                    val uri = URI(url)
                    appendLine("${owner.label}'s room with ${donor.label}'s token:")
                    appendLine("${uri.scheme}://${uri.rawAuthority}${AuthTokens.queryPath(path(uri), mapOf("jwt" to jwt))}\n")
                    count++
                }
            }
            if (count == 0) appendLine("No same-origin room/JWT pairs captured yet. Open JWT-protected room pages or observe /xmpp-websocket?room=...&token=... through Burp. BOSH sid/rid and SASL stream state require a fresh protocol login.")
        }
    }
}
