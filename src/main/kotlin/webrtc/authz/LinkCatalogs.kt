package webrtc.authz

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import webrtc.config.ConfigStore
import webrtc.config.Roles
import webrtc.scope.ScopeGate
import java.net.URI
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import kotlin.math.ln

/** A meeting / invite link seen in the browser, plus the API requests that validated its token. */
data class InviteLink(
    val id: Long, val pageUrl: String, val tokenName: String, val token: String, val location: String,
    val firstSeen: Instant, val page: HttpRequest, val validations: List<HttpRequest> = emptyList()
) {
    val bits: Double get() = Tokens.entropyBits(token)
    val guessability: String get() = Tokens.describe(token)
}

/** A downloadable document, attachment, transcript or recording and the session that fetched it. */
data class Artifact(val id: Long, val url: String, val kind: String, val request: HttpRequest, val ownerSession: Long?, val firstSeen: Instant)

object Tokens {
    private val queryNames = setOf("token", "jwt", "invite", "invitetoken", "invite_token", "invitation", "key", "code", "t",
        "meeting", "meetingid", "meeting_id", "room", "roomid", "room_id", "m", "s", "link", "hash", "pin", "pwd", "password",
        "access", "accesscode", "access_code", "ticket", "visit", "consultation", "appointment")
    private val pathParents = setOf("join", "invite", "invitation", "meeting", "meetings", "room", "rooms", "call", "calls", "m", "j",
        "v", "visit", "session", "consultation", "appointment", "video", "meet", "conference", "c", "r")
    private val tokenText = Regex("[A-Za-z0-9_~.-]{6,256}")

    /** (name, value, location) of the first invite-like token in [url]. */
    fun find(url: String): Triple<String, String, String>? = runCatching {
        val uri = URI(url)
        AuthTokens.pairs(uri.rawQuery.orEmpty()).firstOrNull { (k, v) -> k.lowercase() in queryNames && tokenText.matches(v) }
            ?.let { return Triple(it.first, it.second, "query") }
        val segments = uri.rawPath.orEmpty().split('/').filter { it.isNotEmpty() }
        segments.zipWithNext().firstOrNull { (parent, value) ->
            parent.lowercase() in pathParents && tokenText.matches(value) && (value.any(Char::isDigit) || value.length >= 10)
        }
            ?.let { return Triple(it.first, AuthTokens.decode(it.second), "path") }
        null
    }.getOrNull()

    /** Upper bound on randomness from length and character set; real tokens may have less. */
    fun entropyBits(token: String): Double {
        val alphabet = when {
            token.all { it.isDigit() } -> 10
            token.all { it.isDigit() || it in 'a'..'f' } || token.all { it.isDigit() || it in 'A'..'F' } -> 16
            token.all { it.isDigit() || it.isLowerCase() } || token.all { it.isDigit() || it.isUpperCase() } -> 36
            token.all { it.isLetterOrDigit() } -> 62
            else -> 64
        }
        return token.length * ln(alphabet.toDouble()) / ln(2.0)
    }
    fun describe(token: String): String {
        val bits = entropyBits(token)
        return when {
            AuthTokens.jwtClaims(token) != null -> "JWT (signature-protected; check expiry and audience)"
            token.all { it.isDigit() } && token.length <= 10 -> "Guessable: ${token.length}-digit number (about ${bits.toInt()} bits)"
            bits < 64 -> "Weak: at most ${bits.toInt()} bits"
            else -> "At most ${bits.toInt()} bits (length/charset estimate)"
        }
    }
    /** Changes one character so the token keeps its format but no longer matches. */
    fun altered(token: String): String {
        val last = token.last()
        val replacement = when { last.isDigit() -> if (last == '9') '0' else last + 1; last.isLetter() -> if (last == 'z' || last == 'Z') last - 1 else last + 1; else -> 'A' }
        return token.dropLast(1) + replacement
    }
}

/** Passive catalogs; nothing here sends traffic. Entries are memory-only and bounded. */
class LinkCatalogs(private val config: ConfigStore, private val scope: ScopeGate) {
    private val invites = LinkedHashMap<String, InviteLink>()
    private val artifacts = LinkedHashMap<String, Artifact>()
    private var nextId = 0L
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()
    fun onChange(listener: () -> Unit) { listeners += listener }
    private fun changed() = listeners.forEach { runCatching(it) }
    private fun allowed(url: String) = runCatching { ScopeGate.hostAllowed(URI(url).host, config.config.hostAllowList) && scope.inScope(url) }.getOrDefault(false)

    @Synchronized fun invites(): List<InviteLink> = invites.values.toList().asReversed()
    @Synchronized fun artifacts(): List<Artifact> = artifacts.values.toList().asReversed()
    @Synchronized fun clear() { invites.clear(); artifacts.clear(); changed() }

    @Synchronized fun observe(req: HttpRequest, contentType: String, status: Int, contentDisposition: String = "", ownerSession: Long? = null) {
        val url = req.url()
        if (!allowed(url) || status !in 200..399) return
        if (req.method() == "GET" && contentType.contains("html", true)) {
            Tokens.find(url)?.let { (name, token, location) ->
                val key = "$name|$token"
                if (key !in invites) {
                    invites[key] = InviteLink(++nextId, url, name, token, location, Instant.now(), req)
                    while (invites.size > 50) invites.remove(invites.keys.first())
                    changed()
                }
                return
            }
        }
        // API calls that carry a known invite token are the server-side validation of that link.
        if (!contentType.contains("html", true)) {
            val text = url + "\n" + req.bodyToString().take(65536)
            invites.entries.firstOrNull { (_, link) -> link.token.length >= 6 && text.contains(link.token) }?.let { entry ->
                val link = entry.value
                if (link.validations.none { it.method() == req.method() && it.url() == url } && link.validations.size < 3 && req.method() in setOf("GET", "HEAD", "POST")) {
                    entry.setValue(link.copy(validations = link.validations + req)); changed()
                }
            }
        }
        if (req.method() == "GET" && status in 200..299) artifactKind(url, contentType, contentDisposition)?.let { kind ->
            val key = url.substringBefore('#')
            if (key !in artifacts) {
                artifacts[key] = Artifact(++nextId, url, kind, req, ownerSession, Instant.now())
                while (artifacts.size > 50) artifacts.remove(artifacts.keys.first())
                changed()
            }
        }
    }

    companion object {
        private val staticPath = Regex("(?i)\\.(js|mjs|css|woff2?|ttf|eot|map|ico|svg)(\\?|$)|/(static|assets|_next|build|dist|fonts?)/")
        private val documentPath = Regex("(?i)/(documents?|files?|attachments?|uploads?|downloads?|recordings?|transcripts?|statements?|contracts?|kyc|identity|id-?documents?|media|exports?|archives?)(/|\\?|$)")
        fun artifactKind(url: String, contentType: String, disposition: String): String? {
            if (staticPath.containsMatchIn(url)) return null
            val ct = contentType.lowercase()
            return when {
                disposition.contains("attachment", true) -> "attachment"
                ct.startsWith("application/pdf") -> "document (PDF)"
                ct.startsWith("audio/") || ct.startsWith("video/") -> if (Regex("(?i)record|transcript|archive").containsMatchIn(url)) "recording" else "media file"
                ct.contains("officedocument") || ct.contains("msword") || ct.startsWith("text/csv") || ct.contains("zip") -> "document"
                ct.startsWith("application/octet-stream") -> "file"
                ct.startsWith("image/") && documentPath.containsMatchIn(url) -> "uploaded image"
                documentPath.containsMatchIn(url) && !ct.contains("html") && !ct.contains("json") -> "file"
                else -> null
            }
        }
        /** Seconds a signed download link stays valid, when its query declares it. */
        fun signedLifetime(url: String): Long? = runCatching {
            val query = AuthTokens.pairs(URI(url).rawQuery.orEmpty()).associate { it.first.lowercase() to it.second }
            query["x-amz-expires"]?.toLongOrNull()
                ?: query["expires"]?.toLongOrNull()?.let { it - Instant.now().epochSecond }
                ?: query["se"]?.let { Duration.between(Instant.now(), Instant.parse(it)).seconds }
                ?: query["exp"]?.toLongOrNull()?.let { it - Instant.now().epochSecond }
        }.getOrNull()
        fun isSigned(url: String) = Regex("(?i)[?&](x-amz-signature|signature|sig|x-goog-signature|token|se|expires)=").containsMatchIn(url)
    }
}

/**
 * Replays captured links and downloads. Every request rechecks injection, the host
 * allow-list and Burp Target scope; Stop takes effect between requests. Only GET
 * downloads and the captured validation requests (GET/HEAD/POST) are replayed.
 */
class LinkTester(private val api: MontoyaApi, private val config: ConfigStore, private val scope: ScopeGate) {
    private fun permitted(url: String, shouldContinue: () -> Boolean): Boolean {
        val cfg = config.config
        val host = runCatching { URI(url).host }.getOrNull()
        return shouldContinue() && cfg.injectionEnabled && host != null && ScopeGate.hostAllowed(host, cfg.hostAllowList) && scope.inScope(url)
    }
    private fun skipped(url: String, note: String) = AuthzResult(url, "SKIPPED", 0, 0, "", false, false, note, null)
    private fun hash(text: String) = MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
    private fun stripCredentials(req: HttpRequest): HttpRequest {
        var out = req
        AuthTokens.headers.forEach { if (out.hasHeader(it)) out = out.withRemovedHeader(it) }
        return out
    }

    private fun result(url: String, variant: String, rr: HttpRequestResponse, baseline: HttpRequestResponse, note: String,
                       expectation: String, violationIfSame: Boolean): AuthzResult {
        val resp = rr.response(); val body = resp?.bodyToString().orEmpty()
        val status = resp?.statusCode()?.toInt() ?: 0
        val baseStatus = baseline.response()?.statusCode()?.toInt() ?: 0
        val baseBody = baseline.response()?.bodyToString().orEmpty()
        val same = hash(body) == hash(baseBody)
        val html = resp?.headerValue("Content-Type").orEmpty().contains("html", true)
        val positive = baseStatus in 200..299
        val flagged = variant != "baseline" && positive && status in 200..299 && body.isNotBlank() && !html
        val verdict = when {
            variant.endsWith("baseline") || !positive -> ""
            status in setOf(401, 403, 404, 410) -> AuthzResult.ENFORCED
            flagged && same && violationIfSame -> AuthzResult.LIKELY_VIOLATION
            flagged -> AuthzResult.LEAD
            else -> ""
        }
        val interpretation = when {
            !positive -> "Baseline did not succeed; comparison is inconclusive."
            verdict == AuthzResult.LIKELY_VIOLATION -> "Expected $expectation, but the response is identical to the baseline. Likely broken access control; confirm in Repeater."
            verdict == AuthzResult.ENFORCED -> "Rejected as expected ($expectation)."
            html -> "HTML response; verify actual admission or content in a browser."
            flagged -> "Successful response; expected $expectation. Inspect the content."
            else -> "No verdict."
        }
        return AuthzResult(url, variant, status, body.length, hash(body), same, flagged || verdict == AuthzResult.LIKELY_VIOLATION,
            "$note. $interpretation", rr, baseline, expectation, verdict)
    }

    fun testInvite(link: InviteLink, shouldContinue: () -> Boolean, emit: (AuthzResult) -> Unit, recheck: Boolean = false) {
        val targets = link.validations.ifEmpty { listOf(link.page) }
        for (base in targets) {
            val url = base.url()
            if (!permitted(url, shouldContinue)) { emit(skipped(url, "Meeting link replay needs injection, allow-list, Burp Target scope and continuation")); return }
            val baseRr = api.http().sendRequest(base)
            emit(result(url, if (recheck) "invite:recheck-baseline" else "invite:baseline", baseRr, baseRr,
                "Link ${link.tokenName} (${link.guessability}); validation request as captured", "", false))
            if (recheck) {
                val age = Duration.between(link.firstSeen, Instant.now()).toMinutes()
                val fresh = stripCredentials(base)
                if (!permitted(fresh.url(), shouldContinue)) return
                val rr = api.http().sendRequest(fresh)
                val status = rr.response()?.statusCode()?.toInt() ?: 0
                emit(result(url, "invite:recheck-no-session", rr, baseRr,
                    "Link captured $age minute(s) ago; replayed without session cookies. ${if (status in 200..299) "Still accepted: verify the meeting has ended and whether links should expire after use." else "No longer accepted."}",
                    "link rejected after the meeting ends", false))
                continue
            }
            val variants = listOf(
                Triple("invite:no-session", stripCredentials(base), "token kept, session cookies/headers removed (a fresh visitor)"),
                Triple("invite:token-altered", replaceToken(base, link.token, Tokens.altered(link.token)), "one character of the token changed"),
                Triple("invite:token-removed", replaceToken(base, link.token, ""), "token removed"))
            for ((variant, request, how) in variants) {
                if (request == null) continue
                if (!permitted(request.url(), shouldContinue)) { emit(skipped(request.url(), "Stopped before $variant")); return }
                val rr = api.http().sendRequest(request)
                val deny = variant != "invite:no-session"
                emit(result(url, variant, rr, baseRr, "Link ${link.tokenName}: $how",
                    if (deny) "deny (invalid or missing meeting token)" else "bearer link: works without a session if the design allows it", deny))
            }
        }
    }

    private fun replaceToken(req: HttpRequest, token: String, replacement: String): HttpRequest? {
        val path = req.path(); val body = req.bodyToString()
        if (!path.contains(token) && !body.contains(token)) return null
        val encoded = java.net.URLEncoder.encode(token, Charsets.UTF_8)
        var out = req
        if (path.contains(token)) out = out.withPath(path.replace(token, replacement))
        else if (path.contains(encoded)) out = out.withPath(path.replace(encoded, replacement))
        if (body.contains(token)) out = out.withBody(body.replace(token, replacement))
        return out
    }

    fun testArtifact(artifact: Artifact, others: List<CapturedSession>, owner: CapturedSession?, shouldContinue: () -> Boolean, emit: (AuthzResult) -> Unit) {
        val url = artifact.url
        if (!permitted(url, shouldContinue)) { emit(skipped(url, "Document replay needs injection, allow-list, Burp Target scope and continuation")); return }
        val baseRr = api.http().sendRequest(artifact.request)
        val signed = LinkCatalogs.isSigned(url)
        val lifetime = LinkCatalogs.signedLifetime(url)
        emit(result(url, "artifact:baseline", baseRr, baseRr, "${artifact.kind} as captured" + (owner?.let { " by ${it.label}" } ?: "") +
            (if (signed) "; signed link" + (lifetime?.let { ", valid for about ${it / 3600} hour(s) more" + if (it > 86_400) " (long-lived: review)" else "" } ?: "") else ""), "", false))
        for (session in others.take(6)) {
            if (owner != null && session.id == owner.id) continue
            val request = runCatching { AuthTokens.apply(stripCredentials(artifact.request), session.identity) }.getOrNull() ?: continue
            if (!permitted(request.url(), shouldContinue)) { emit(skipped(url, "Stopped before ${session.label}")); return }
            val rr = api.http().sendRequest(request)
            val ownerRank = Roles.rank(owner?.identity?.role.orEmpty()); val rank = Roles.rank(session.identity.role)
            val expectation = when {
                ownerRank != null && rank != null && rank > ownerRank -> "allowed for a higher role (${session.identity.role})"
                else -> "deny (another user's ${artifact.kind})"
            }
            emit(result(url, "artifact:${session.label}", rr, baseRr, "${artifact.kind} requested with ${session.label}'s credentials", expectation,
                !expectation.startsWith("allowed")))
        }
        val anonymous = stripCredentials(artifact.request)
        if (!permitted(anonymous.url(), shouldContinue)) return
        val rr = api.http().sendRequest(anonymous)
        emit(result(url, "artifact:no-credentials", rr, baseRr, "${artifact.kind} requested without session credentials" +
            if (signed) " (signed link: anyone holding the URL can download it until it expires)" else "",
            if (signed) "bearer signed link" else "deny (no credentials)", !signed))
        neighbour(url)?.let { (lower, higher) ->
            for ((label, next) in listOf("artifact:id-1" to lower, "artifact:id+1" to higher)) {
                val request = artifact.request.withPath(URI(next).rawPath + (URI(next).rawQuery?.let { "?$it" } ?: ""))
                if (!permitted(request.url(), shouldContinue)) return
                val neighbourRr = api.http().sendRequest(request)
                val status = neighbourRr.response()?.statusCode()?.toInt() ?: 0
                emit(result(url, label, neighbourRr, baseRr, "Neighbouring numeric ID ${URI(next).rawPath} with the owner's session. " +
                    if (status in 200..299) "Accessible: confirm whether it belongs to the same user (sequential IDs make enumeration easy)." else "Not returned.",
                    "only the owner's own documents", false))
            }
        }
    }

    private fun neighbour(url: String): Pair<String, String>? = runCatching {
        val uri = URI(url)
        val match = Regex("/(\\d{1,12})(?=/|$)").findAll(uri.rawPath).lastOrNull() ?: return null
        val value = match.groupValues[1].toLong()
        fun with(n: Long) = "${uri.scheme}://${uri.rawAuthority}" + uri.rawPath.replaceRange(match.range, "/$n") + (uri.rawQuery?.let { "?$it" } ?: "")
        with(maxOf(0, value - 1)) to with(value + 1)
    }.getOrNull()
}
