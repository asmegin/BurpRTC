package webrtc.authz

import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.json.*
import webrtc.config.IdentityProfile
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

/** Credentials are parsed by location; replacement never does a global string substitution. */
object AuthTokens {
    val headers = listOf("Authorization", "Cookie", "X-Auth-Token", "X-Api-Key", "X-Access-Token", "X-CSRF-Token", "X-XSRF-Token")
    private val names = setOf("token", "jwt", "access_token", "accesstoken", "auth_token", "authtoken",
        "session_token", "sessiontoken", "id_token", "idtoken", "api_key", "apikey", "session", "session_id", "sessionid", "auth")
    private val csrf = setOf("csrf", "csrf_token", "csrftoken", "xsrf", "xsrf_token", "xsrf-token", "_csrf")
    fun tokenName(name: String) = name.lowercase() in names
    private fun authName(name: String) = tokenName(name) || name.lowercase() in csrf
    fun origin(url: String): String? = runCatching {
        val u = URI(url)
        val scheme = when (u.scheme?.lowercase()) { "ws" -> "http"; "wss" -> "https"; else -> u.scheme?.lowercase() }
        if (scheme !in setOf("http", "https") || u.host == null || u.userInfo != null) null
        else "$scheme://${u.host.lowercase()}:${if (u.port >= 0) u.port else if (scheme == "https") 443 else 80}"
    }.getOrNull()
    fun decode(value: String) = runCatching { URLDecoder.decode(value, UTF_8) }.getOrDefault(value)
    private fun encode(value: String) = URLEncoder.encode(value, UTF_8).replace("+", "%20")
    fun pairs(raw: String): List<Pair<String, String>> = raw.split('&').filter { it.isNotEmpty() }.map {
        decode(it.substringBefore('=')) to decode(it.substringAfter('=', ""))
    }
    private fun rewritePairs(raw: String, values: Map<String, String>, removeAuth: Boolean, removeKeys: Set<String> = emptySet()): String {
        val seen = mutableSetOf<String>()
        val parts = raw.split('&').filter { it.isNotEmpty() }.mapNotNull { part ->
            val key = decode(part.substringBefore('='))
            when {
                key in values -> { seen += key; "${part.substringBefore('=')}=${encode(values.getValue(key))}" }
                removeAuth && (authName(key) || key in removeKeys) -> null
                else -> part
            }
        }.toMutableList()
        values.filterKeys { it !in seen }.forEach { (key, value) -> parts += "${encode(key)}=${encode(value)}" }
        return parts.joinToString("&")
    }
    fun queryPath(path: String, values: Map<String, String>, removeAuth: Boolean = true, removeKeys: Set<String> = emptySet()): String {
        val base = path.substringBefore('?')
        val query = rewritePairs(path.substringAfter('?', ""), values, removeAuth, removeKeys)
        return base + if (query.isEmpty()) "" else "?$query"
    }

    private fun jsonTokens(node: JsonElement, pointer: String = "", depth: Int = 0): Map<String, String> {
        if (depth > 12) return emptyMap()
        return when (node) {
            is JsonObject -> node.entries.flatMap { (key, value) ->
                val p = "$pointer/${key.replace("~", "~0").replace("/", "~1")}"
                if (authName(key) && value is JsonPrimitive && value.isString) listOf(p to value.content)
                else jsonTokens(value, p, depth + 1).toList()
            }.toMap()
            is JsonArray -> node.take(512).flatMapIndexed { index, value -> jsonTokens(value, "$pointer/$index", depth + 1).toList() }.toMap()
            else -> emptyMap()
        }
    }
    fun capture(req: HttpRequest, name: String = "captured"): IdentityProfile {
        val h = headers.mapNotNull { key -> req.headerValue(key)?.takeIf { it.isNotBlank() }?.let { key to it } }.toMap()
        val query = pairs(req.path().substringAfter('?', "")).filter { authName(it.first) && it.second.isNotEmpty() }.toMap()
        val body = req.bodyToString()
        val ct = req.headerValue("Content-Type").orEmpty()
        val tokens = when {
            body.length > 262144 -> emptyMap()
            ct.contains("json", true) -> runCatching { jsonTokens(Json.parseToJsonElement(body)) }.getOrDefault(emptyMap())
            ct.contains("application/x-www-form-urlencoded", true) -> pairs(body).filter { authName(it.first) && it.second.isNotEmpty() }.toMap()
            else -> emptyMap()
        }
        return IdentityProfile(name, h, queryTokens = query, bodyTokens = tokens, origins = listOfNotNull(origin(req.url())))
    }
    fun hasCredentials(id: IdentityProfile) = id.headers.keys.any { !it.equals("X-CSRF-Token", true) && !it.equals("X-XSRF-Token", true) } ||
        id.queryTokens.keys.any { it.lowercase() !in csrf } || id.bodyTokens.keys.any { it.substringAfterLast('/').lowercase() !in csrf }
    fun values(id: IdentityProfile): List<String> = id.headers.values.flatMap { value ->
        listOf(value.replaceFirst(Regex("(?i)^Bearer\\s+"), "")) + value.split(';').map { it.trim().substringAfter('=', "") }
    } + id.queryTokens.values + id.bodyTokens.values
    fun jwtClaims(value: String): JsonObject? = runCatching {
        val parts = value.split('.')
        if (parts.size != 3 || parts[1].length > 65536) null else
            Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(parts[1]), UTF_8)) as? JsonObject
    }.getOrNull()
    fun sameCredentials(source: IdentityProfile, donor: IdentityProfile): Boolean {
        val a = values(source).filter { jwtClaims(it) != null }.toSet()
        val b = values(donor).filter { jwtClaims(it) != null }.toSet()
        if (a.intersect(b).isNotEmpty()) return true
        fun identity(id: IdentityProfile) = Triple(id.headers.filterKeys { !it.contains("csrf", true) && !it.contains("xsrf", true) },
            id.queryTokens.filterKeys(::tokenName), id.bodyTokens.filterKeys { tokenName(it.substringAfterLast('/')) })
        return hasCredentials(source) && identity(source) == identity(donor)
    }

    /** Source credentials are removed before installing a donor; CSRF headers travel with cookies. */
    fun apply(req: HttpRequest, id: IdentityProfile?, knownQueryKeys: Set<String> = emptySet(), knownBodyKeys: Set<String> = emptySet()): HttpRequest {
        val original = capture(req)
        var out = req
        val clearHeaders = headers + listOf("X-CSRF-Token", "X-XSRF-Token") + id?.headers.orEmpty().keys
        clearHeaders.distinct().forEach { if (out.hasHeader(it)) out = out.withRemovedHeader(it) }
        id?.headers.orEmpty().forEach { (key, value) -> out = out.withAddedHeader(key, value) }
        val path = queryPath(req.path(), id?.queryTokens.orEmpty(), removeKeys = knownQueryKeys)
        if (path != req.path()) out = out.withPath(path)
        val body = req.bodyToString()
        val ct = req.headerValue("Content-Type").orEmpty()
        val replacement = when {
            body.length > 262144 -> {
                error("Body exceeds token parser limit")
            }
            ct.contains("json", true) -> {
                val node = runCatching { Json.parseToJsonElement(body) }.getOrNull()
                val values = id?.bodyTokens.orEmpty()
                require(values.keys.all { it.startsWith('/') && node != null && webrtc.assessment.JsonPointer.get(node, it) is JsonPrimitive }) { "Donor JSON token locations do not match this request" }
                fun rewrite(n: JsonElement, p: String = "", depth: Int = 0): JsonElement {
                    if (depth > 12) return n
                    return when (n) {
                        is JsonObject -> JsonObject(n.mapNotNull { (key, value) ->
                            val child = "$p/${key.replace("~", "~0").replace("/", "~1")}"
                            when { child in values -> key to JsonPrimitive(values.getValue(child))
                                child in original.bodyTokens || child in knownBodyKeys -> null
                                else -> key to rewrite(value, child, depth + 1) }
                        }.toMap())
                        is JsonArray -> JsonArray(n.mapIndexed { index, value -> rewrite(value, "$p/$index", depth + 1) })
                        else -> n
                    }
                }
                if (node == null || (original.bodyTokens.isEmpty() && values.isEmpty() && knownBodyKeys.isEmpty())) body else rewrite(node).toString()
            }
            ct.contains("application/x-www-form-urlencoded", true) -> {
                require(id?.bodyTokens.orEmpty().keys.none { it.startsWith('/') }) { "JSON token cannot be applied to form data" }
                rewritePairs(body, id?.bodyTokens.orEmpty(), true, knownBodyKeys)
            }
            else -> { require(id?.bodyTokens.orEmpty().isEmpty()) { "Unsupported authentication body format" }; body }
        }
        if (replacement != body) out = out.withBody(replacement)
        return out
    }
}
