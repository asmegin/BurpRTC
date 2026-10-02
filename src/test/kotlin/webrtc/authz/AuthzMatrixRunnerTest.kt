package webrtc.authz

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import webrtc.config.ConfigStore
import webrtc.scope.ScopeGate
import java.lang.reflect.Proxy
import kotlin.test.*

class AuthzMatrixRunnerTest {
    private class Harness {
        var persisted: String? = null
        var inScope = true
        var sends = 0
        val request = proxy(HttpRequest::class.java) { name -> when (name) {
            "url" -> "https://app.test/api"; "hasHeader" -> false; else -> null
        } }
        val response = proxy(HttpResponse::class.java) { name -> when (name) {
            "statusCode" -> 403.toShort(); "bodyToString" -> "denied"; else -> null
        } }
        val exchange = proxy(HttpRequestResponse::class.java) { name -> when (name) {
            "request" -> request; "response" -> response; else -> null
        } }
        fun apiProxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when (method.name) {
                "getString" -> persisted
                "setString" -> { persisted = args!![1] as String; null }
                "isInScope" -> inScope
                "sendRequest" -> { sends++; exchange }
                else -> if (method.returnType.isInterface) apiProxy(method.returnType) else null
            }
        }
        val api = apiProxy(MontoyaApi::class.java) as MontoyaApi
        val store = ConfigStore(api).also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("app.test"))) }
        val runner = AuthzMatrixRunner(api, store, ScopeGate(api))
        companion object {
            private fun <T> proxy(type: Class<T>, result: (String) -> Any?): T = type.cast(
                Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ -> result(method.name) })
        }
    }

    @Test fun `all three authorization gates and continuation are required before replay`() {
        for (gate in listOf("scope", "injection", "allow-list", "stop")) {
            val h = Harness()
            when (gate) {
                "scope" -> h.inScope = false
                "injection" -> h.store.save(h.store.config.copy(injectionEnabled = false))
                "allow-list" -> h.store.save(h.store.config.copy(hostAllowList = listOf("other.test")))
            }
            val results = mutableListOf<AuthzResult>()
            h.runner.run(h.request, { gate != "stop" }, results::add)
            assertEquals(0, h.sends, gate)
            assertEquals("SKIPPED", results.single().variant)
        }
    }

    @Test fun `scope or config revocation after baseline blocks subsequent replays`() {
        for (gate in listOf("scope", "injection", "allow-list")) {
            val h = Harness()
            val results = mutableListOf<AuthzResult>()
            h.runner.run(h.request, { true }) {
                results += it
                when (gate) {
                    "scope" -> h.inScope = false
                    "injection" -> h.store.save(h.store.config.copy(injectionEnabled = false))
                    "allow-list" -> h.store.save(h.store.config.copy(hostAllowList = emptyList()))
                }
            }
            assertEquals(1, h.sends, gate)
            assertEquals(listOf("baseline", "SKIPPED"), results.map { it.variant })
        }
    }

    @Test fun `permitted replay describes authentication stripping limits`() {
        val h = Harness()
        val results = mutableListOf<AuthzResult>()
        h.runner.run(h.request, { true }, results::add)
        assertEquals(2, h.sends)
        assertEquals(listOf("baseline", "unauth"), results.map { it.variant })
        assertTrue(results.last().note.contains("URL/body tokens"))
    }
}
