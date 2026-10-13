package webrtc.authz

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import webrtc.config.ConfigStore
import webrtc.scope.ScopeGate
import java.lang.reflect.Proxy
import java.net.URI

internal fun request(url: String = "https://app.test/api/resource", method: String = "GET",
                     headers: Map<String, String> = emptyMap(), body: String = ""): HttpRequest {
    return HttpRequest::class.java.cast(Proxy.newProxyInstance(HttpRequest::class.java.classLoader, arrayOf(HttpRequest::class.java)) { obj, m, args ->
        fun key(name: String) = headers.keys.firstOrNull { it.equals(name, true) }
        when (m.name) {
            "url" -> url
            "path" -> URI(url).let { it.rawPath + if (it.rawQuery == null) "" else "?${it.rawQuery}" }
            "method" -> method
            "bodyToString" -> body
            "hasHeader" -> key(args!![0] as String) != null
            "headerValue" -> key(args!![0] as String)?.let { headers[it] }
            "withRemovedHeader" -> request(url, method, headers.filterKeys { !it.equals(args!![0] as String, true) }, body)
            "withAddedHeader", "withUpdatedHeader" -> request(url, method, headers.filterKeys { !it.equals(args!![0] as String, true) } +
                ((args!![0] as String) to (args[1] as String)), body)
            "withBody" -> request(url, method, headers, args!![0] as String)
            "withPath" -> request(URI(url).let { "${it.scheme}://${it.rawAuthority}${args!![0]}" }, method, headers, body)
            "toString" -> "$method $url\n${headers.entries.joinToString("\n") { "${it.key}: ${it.value}" }}\n\n$body"
            "equals" -> obj === args?.get(0)
            "hashCode" -> System.identityHashCode(obj)
            else -> error("Unexpected request call: ${m.name}")
        }
    })
}

internal class AuthzFixture {
    var inScope = true
    val sent = mutableListOf<HttpRequest>()
    private val persistence = mutableMapOf<String, String>()
    var response: (HttpRequest) -> Pair<Int, String> = { 200 to "{\"owner\":\"alice\",\"private\":true}" }
    var contentType = "application/json"
    fun apiProxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, m, args ->
        when (m.name) {
            "getString" -> persistence[args!![0]]
            "setString" -> { persistence[args!![0] as String] = args[1] as String; null }
            "isInScope" -> inScope
            "sendRequest" -> {
                val req = args!![0] as HttpRequest; sent += req
                val (status, body) = response(req)
                val resp = Proxy.newProxyInstance(HttpResponse::class.java.classLoader, arrayOf(HttpResponse::class.java)) { _, rm, _ ->
                    when (rm.name) { "statusCode" -> status.toShort(); "bodyToString" -> body; "headerValue" -> contentType; "toString" -> "HTTP $status\n\n$body"; else -> null }
                }
                Proxy.newProxyInstance(HttpRequestResponse::class.java.classLoader, arrayOf(HttpRequestResponse::class.java)) { _, em, _ ->
                    when (em.name) { "request" -> req; "response" -> resp; else -> null }
                }
            }
            else -> if (m.returnType.isInterface) apiProxy(m.returnType) else null
        }
    }
    val api = apiProxy(MontoyaApi::class.java) as MontoyaApi
    val config = ConfigStore(api).also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("app.test", "other.test"))) }
    val scope = ScopeGate(api)
    val catalog = SessionCatalog(config, scope)
    val runner = AuthzMatrixRunner(api, config, scope)
}
