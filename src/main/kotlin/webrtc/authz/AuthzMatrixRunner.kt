package webrtc.authz

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import webrtc.config.IdentityProfile
import webrtc.config.ConfigStore
import webrtc.scope.ScopeGate
import java.security.MessageDigest
import java.net.URI

data class AuthzResult(
    val baselineUrl: String,
    val variant: String,
    val status: Int,
    val length: Int,
    val bodyHash: String,
    val sameAsBaseline: Boolean,
    val flagged: Boolean,
    val note: String,
    val requestResponse: HttpRequestResponse?,
    val baselineRequestResponse: HttpRequestResponse? = null,
    /** What the tester's role labels or the variant imply should happen, for example "deny (lower role)". */
    val expectation: String = "",
    /** LIKELY_VIOLATION, LEAD, ENFORCED, PUBLIC or blank when no verdict can be drawn. */
    val verdict: String = ""
) {
    companion object {
        const val LIKELY_VIOLATION = "likely violation"
        const val LEAD = "review lead"
        const val ENFORCED = "access denied"
        const val PUBLIC = "public resource"
    }
}

/**
 * M5 — the authorization matrix. For a baseline request it replays:
 *  (a) unchanged under every other identity,
 *  (b) current identity with each other principal's identifiers substituted,
 *  (c) unauthenticated.
 * Cross-principal 2xx responses are flagged. All replays are scope-gated.
 */
class AuthzMatrixRunner(
    private val api: MontoyaApi,
    private val configStore: ConfigStore,
    private val scope: ScopeGate
) {
    fun run(baseline: HttpRequestResponse, onResult: (AuthzResult) -> Unit) = run(baseline.request(), { true }, onResult)

    fun run(baseReq: HttpRequest, shouldContinue: () -> Boolean, onResult: (AuthzResult) -> Unit) =
        run(baseReq, configStore.config.identities, "captured request", shouldContinue, true, onResult = onResult)

    fun run(baseReq: HttpRequest, identities: List<IdentityProfile>, owner: String, shouldContinue: () -> Boolean,
            substituteIds: Boolean = false, ownerProfile: IdentityProfile? = null, onResult: (AuthzResult) -> Unit) {
        // Identity replays are held until the credential-free control returns, so a
        // resource that answers without credentials is labelled public, not a violation.
        val pending = mutableListOf<AuthzResult>()
        val emit: (AuthzResult) -> Unit = { result -> if (result.variant.startsWith("identity:") || result.variant.startsWith("sub:")) pending += result else { flushPending(pending, null, onResult); onResult(result) } }
        try { runMatrix(baseReq, identities, owner, shouldContinue, substituteIds, ownerProfile, emit) { publicBody -> flushPending(pending, publicBody, onResult) } }
        finally { flushPending(pending, null, onResult) }
    }

    private fun flushPending(pending: MutableList<AuthzResult>, publicHash: String?, onResult: (AuthzResult) -> Unit) {
        if (pending.isEmpty()) return
        val copy = pending.toList(); pending.clear()
        copy.forEach { result ->
            onResult(if (publicHash != null && result.flagged && result.bodyHash == publicHash)
                result.copy(verdict = AuthzResult.PUBLIC, note = result.note + " The credential-free control returned the same body, so this resource appears public.")
            else result)
        }
    }

    private fun runMatrix(baseReq: HttpRequest, identities: List<IdentityProfile>, owner: String, shouldContinue: () -> Boolean,
                          substituteIds: Boolean, ownerProfile: IdentityProfile?, onResult: (AuthzResult) -> Unit, onControl: (String?) -> Unit) {
        val cfg = configStore.config
        val url = baseReq.url()
        val captured = AuthTokens.capture(baseReq)
        val ownerIdentity = ownerProfile ?: (identities + cfg.identities).firstOrNull { AuthTokens.hasCredentials(it) && AuthTokens.sameCredentials(captured, it) }
        val markers = ownerMarkers(ownerIdentity ?: captured)
        // BOSH streams and WS upgrade requests need a fresh protocol login, not HTTP replay.
        if (baseReq.hasHeader("Upgrade") || Regex("(?i)(?:^|/)(?:http-bind|xmpp-websocket)(?:[/?]|$)").containsMatchIn(baseReq.path())) {
            onResult(AuthzResult(url, "SKIPPED", 0, 0, "", false, false,
                "$owner: XMPP/WS connection state requires a fresh login. Use Prepare room swaps for captured Jitsi JWTs.", null))
            return
        }

        fun permitted(requestUrl: String): Boolean {
            val current = configStore.config
            val host = runCatching { URI(requestUrl).host }.getOrNull()
            val allowed = shouldContinue() && current.injectionEnabled && host != null &&
                ScopeGate.hostAllowed(host, current.hostAllowList) && scope.inScope(requestUrl)
            if (!allowed) onResult(AuthzResult(requestUrl, "SKIPPED", 0, 0, "", false, false,
                "Replay stopped: injection, host allow-list, Burp Target scope and continuation permission are required before every request", null))
            return allowed
        }
        if (!permitted(url)) return

        val baseRr = api.http().sendRequest(baseReq)
        val baseBody = baseRr.response()?.bodyToString() ?: ""
        val baseHash = sha256(baseBody)
        val presentMarkers = markers.filter { baseBody.contains(it) }
        onResult(toResult(url, "baseline", baseRr, baseRr, baseHash, "$owner: positive control" +
            if (presentMarkers.isNotEmpty()) "; owner-identifying values in body: ${presentMarkers.joinToString(", ")}" else ""))
        fun expectation(replay: IdentityProfile?): String {
            val ownerRank = webrtc.config.Roles.rank(ownerIdentity?.role.orEmpty())
            val replayRank = replay?.let { webrtc.config.Roles.rank(it.role) }
            return when {
                replay == null -> "deny (no credentials)"
                ownerRank != null && replayRank != null && replayRank < ownerRank -> "deny (lower role ${replay.role} reading ${ownerIdentity?.role} data)"
                ownerRank != null && replayRank != null && replayRank == ownerRank && replay.role.equals("customer", true) -> "deny (another customer's data)"
                else -> ""
            }
        }
        val customHeaders = (cfg.identities + identities).flatMap { it.headers.keys }.distinct()
        val queryKeys = (cfg.identities + identities).flatMap { it.queryTokens.keys }.toSet()
        val bodyKeys = (cfg.identities + identities).flatMap { it.bodyTokens.keys }.toSet()
        fun asIdentity(id: IdentityProfile?): HttpRequest {
            var req = baseReq
            for (header in customHeaders) if (req.hasHeader(header)) req = req.withRemovedHeader(header)
            return AuthTokens.apply(req, id, queryKeys, bodyKeys)
        }

        // (a) unchanged, under every other identity
        for (id in identities.take(20)) {
            if (!AuthTokens.hasCredentials(id) || AuthTokens.sameCredentials(AuthTokens.capture(baseReq), id)) {
                onResult(AuthzResult(url, "SKIPPED", 0, 0, "", false, false,
                    "$owner → ${id.name}: no distinct reusable HTTP credential; XMPP-only observations require a fresh protocol login", null))
                continue
            }
            val origin = AuthTokens.origin(url)
            if (id.origins.isNotEmpty() && id.origins.none { AuthTokens.origin(it) == origin }) {
                onResult(AuthzResult(url, "SKIPPED", 0, 0, "", false, false,
                    "$owner → ${id.name}: credentials belong to a different origin", null))
                continue
            }
            val attempt = runCatching { asIdentity(id) }
            val req = attempt.getOrNull()
            if (req == null) {
                onResult(AuthzResult(url, "SKIPPED", 0, 0, "", false, false, "$owner → ${id.name}: ${attempt.exceptionOrNull()?.message}", null))
                continue
            }
            if (!permitted(req.url())) return
            val rr = api.http().sendRequest(req)
            onResult(toResult(url, "identity:${id.name}", rr, baseRr, baseHash, "$owner → ${id.name}; resource identifiers unchanged",
                expectation(id), presentMarkers))
        }

        // (b) current identity, other principals' identifiers substituted
        for (id in if (substituteIds) identities else emptyList()) {
            if (id.origins.isNotEmpty() && id.origins.none { AuthTokens.origin(it) == AuthTokens.origin(url) }) continue
            val req = substituteIdentifiers(baseReq, id, cfg.identifierKeys) ?: continue
            if (!permitted(req.url())) return
            val rr = api.http().sendRequest(req)
            onResult(toResult(url, "sub:${id.name}", rr, baseRr, baseHash, "identifiers set to ${id.name}'s values"))
        }

        // (c) unauthenticated
        val unauth = asIdentity(null)
        if (!permitted(unauth.url())) return
        val rrUnauth = api.http().sendRequest(unauth)
        val unauthResult = toResult(url, "unauth", rrUnauth, baseRr, baseHash,
            "$owner → no credentials; known headers and recognized URL/body tokens removed; unrecognized authentication requires separate review",
            expectation(null), presentMarkers)
        onControl(if (unauthResult.flagged && unauthResult.sameAsBaseline && presentMarkers.isEmpty()) unauthResult.bodyHash else null)
        onResult(unauthResult)
    }

    /** Values that identify the baseline principal (JWT subject/email/name claims and configured identifiers). */
    private fun ownerMarkers(identity: IdentityProfile): Set<String> {
        val claimKeys = setOf("sub", "email", "name", "preferred_username", "user_id", "userId", "uid", "customer_id", "customerId", "account", "accountId", "client_id")
        val claims: List<String> = AuthTokens.values(identity).mapNotNull(AuthTokens::jwtClaims).flatMap { claims: JsonObject ->
            val user = (claims["context"] as? JsonObject)?.get("user") as? JsonObject
            val elements: List<JsonElement> = claimKeys.mapNotNull { claims[it] } + listOf("id", "email", "name").mapNotNull { user?.get(it) }
            elements.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        }
        return (claims + identity.identifiers.values).map { it.trim() }.filter { it.length >= 4 }.toSet()
    }

    private fun toResult(
        url: String,
        variant: String,
        rr: HttpRequestResponse,
        baseline: HttpRequestResponse,
        baseHash: String,
        note: String,
        expectation: String = "",
        ownerMarkersInBaseline: List<String> = emptyList()
    ): AuthzResult {
        val resp = rr.response()
        val body = resp?.bodyToString() ?: ""
        val hash = sha256(body)
        val status = resp?.statusCode()?.toInt() ?: 0
        val is2xx = status in 200..299
        val same = hash == baseHash
        val positive = baseline.response()?.statusCode()?.toInt() in 200..299
        val html = resp?.headerValue("Content-Type").orEmpty().contains("html", true) || body.trimStart().startsWith("<!doctype html", true)
        val flagged = variant != "baseline" && positive && is2xx && !html && body.isNotBlank()
        val interpretation = when {
            !positive -> "Baseline did not succeed; comparison is inconclusive."
            html -> "HTML page/shell response; verify protected content or actual room admission."
            variant != "baseline" && status in setOf(401, 403) -> "HTTP rejection observed; verify the same resource and policy."
            flagged && same -> "Same response body: review possible shared protected content; confirm different principals and ownership."
            flagged -> "Successful response differs: inspect protected content; an application error can also return 2xx."
            else -> "No authorization verdict established."
        }
        val leaked = ownerMarkersInBaseline.filter { body.contains(it) }
        val verdict = when {
            variant == "baseline" || !positive -> ""
            variant != "baseline" && status in setOf(401, 403) -> AuthzResult.ENFORCED
            flagged && expectation.isNotEmpty() && leaked.isNotEmpty() -> AuthzResult.LIKELY_VIOLATION
            flagged && expectation.startsWith("deny (lower role") && same -> AuthzResult.LIKELY_VIOLATION
            flagged -> AuthzResult.LEAD
            else -> ""
        }
        val verdictText = when (verdict) {
            AuthzResult.LIKELY_VIOLATION -> " Expected $expectation, but the response " + (if (leaked.isNotEmpty()) "contains the baseline owner's values (${leaked.joinToString(", ")})." else "matches the higher-privilege baseline.") + " Likely broken access control; confirm in Repeater."
            else -> if (expectation.isNotEmpty()) " Expected: $expectation." else ""
        }
        val storedRr = runCatching { rr.copyToTempFile() ?: rr }.getOrDefault(rr)
        val storedBase = if (baseline === rr) storedRr else runCatching { baseline.copyToTempFile() ?: baseline }.getOrDefault(baseline)
        return AuthzResult(url, variant, status, body.length, hash, same, flagged, "$note. $interpretation$verdictText", storedRr, storedBase, expectation, verdict)
    }

    private fun substituteIdentifiers(
        req: HttpRequest,
        target: IdentityProfile,
        keys: List<String>
    ): HttpRequest? {
        val originalPath = req.path()
        val originalBody = req.bodyToString()
        var newPath = originalPath
        var newBody = originalBody
        for (key in keys) {
            val tgt = target.identifiers[key] ?: continue
            if (tgt.isBlank()) continue
            for (src in configStore.config.identities) {
                if (src.name == target.name) continue
                val sv = src.identifiers[key] ?: continue
                if (sv.isBlank() || sv == tgt) continue
                if (newPath.contains(sv)) newPath = newPath.replace(sv, tgt)
                if (newBody.contains(sv)) newBody = newBody.replace(sv, tgt)
            }
        }
        if (newPath == originalPath && newBody == originalBody) return null
        var r = req
        if (newPath != originalPath) r = r.withPath(newPath)
        if (newBody != originalBody) r = r.withBody(newBody)
        return r
    }

    private fun sha256(s: String): String {
        val d = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
        return d.joinToString("") { "%02x".format(it) }.take(16)
    }
}
