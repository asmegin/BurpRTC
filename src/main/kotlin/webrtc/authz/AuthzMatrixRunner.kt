package webrtc.authz

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
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
    val requestResponse: HttpRequestResponse?
)

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
    private val authHeaders = listOf("Authorization", "Cookie", "X-Auth-Token", "X-Api-Key")

    fun run(baseline: HttpRequestResponse, onResult: (AuthzResult) -> Unit) = run(baseline.request(), { true }, onResult)

    fun run(baseReq: HttpRequest, shouldContinue: () -> Boolean, onResult: (AuthzResult) -> Unit) {
        val cfg = configStore.config
        val url = baseReq.url()

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
        onResult(toResult(url, "baseline", baseRr, baseHash, baseHash, "baseline"))

        // (a) unchanged, under every other identity
        for (id in cfg.identities) {
            if (!permitted(url)) return
            val rr = api.http().sendRequest(applyIdentity(baseReq, id))
            onResult(toResult(url, "identity:${id.name}", rr, baseHash, null, "unchanged request as ${id.name}"))
        }

        // (b) current identity, other principals' identifiers substituted
        for (id in cfg.identities) {
            val req = substituteIdentifiers(baseReq, id, cfg.identifierKeys) ?: continue
            if (!permitted(req.url())) return
            val rr = api.http().sendRequest(req)
            onResult(toResult(url, "sub:${id.name}", rr, baseHash, null, "identifiers set to ${id.name}'s values"))
        }

        // (c) unauthenticated
        if (!permitted(url)) return
        val rrUnauth = api.http().sendRequest(stripAuth(baseReq))
        onResult(toResult(url, "unauth", rrUnauth, baseHash, null,
            "known authentication headers stripped; URL/body tokens and application-specific authentication require separate review"))
    }

    private fun toResult(
        url: String,
        variant: String,
        rr: HttpRequestResponse,
        baseHash: String,
        forcedHash: String?,
        note: String
    ): AuthzResult {
        val resp = rr.response()
        val body = resp?.bodyToString() ?: ""
        val hash = forcedHash ?: sha256(body)
        val status = resp?.statusCode()?.toInt() ?: 0
        val is2xx = status in 200..299
        val same = hash == baseHash
        // Flag any non-baseline variant that returns 2xx (a principal that shouldn't
        // have access getting one is the signal); body-match strengthens it.
        val flagged = variant != "baseline" && is2xx
        return AuthzResult(url, variant, status, body.length, hash, same, flagged, note, rr)
    }

    private fun applyIdentity(req: HttpRequest, id: IdentityProfile): HttpRequest {
        var r = req
        // Clear existing auth so the profile fully defines the identity.
        for (h in authHeaders) if (r.hasHeader(h)) r = r.withRemovedHeader(h)
        for ((name, value) in id.headers) {
            r = if (r.hasHeader(name)) r.withUpdatedHeader(name, value) else r.withAddedHeader(name, value)
        }
        return r
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

    private fun stripAuth(req: HttpRequest): HttpRequest {
        var r = req
        for (h in authHeaders) if (r.hasHeader(h)) r = r.withRemovedHeader(h)
        return r
    }

    private fun sha256(s: String): String {
        val d = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
        return d.joinToString("") { "%02x".format(it) }.take(16)
    }
}
