package webrtc.inject

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import webrtc.config.ConfigStore
import webrtc.scope.ScopeGate
import java.lang.reflect.Proxy
import kotlin.test.*

class InjectorHandlerTest {
    private var inScope = true
    private val url = "https://video.example/call"
    private val html = "<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\"></head><body>video</body></html>"

    private fun <T> proxy(type: Class<T>, handler: (String, Array<out Any?>?) -> Any?): T =
        type.cast(Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args -> handler(method.name, args) })

    private fun api(): MontoyaApi {
        fun stub(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ ->
            when {
                method.name == "isInScope" -> inScope
                method.name == "getString" -> null
                method.returnType.isInterface -> stub(method.returnType)
                else -> null
            }
        }
        return stub(MontoyaApi::class.java) as MontoyaApi
    }

    private fun header(name: String, value: String): HttpHeader = proxy(HttpHeader::class.java) { method, _ ->
        when (method) {
            "name" -> name
            "value" -> value
            else -> error("Unexpected header method: $method")
        }
    }

    private fun response(headers: List<HttpHeader>, body: String = html): HttpResponseReceived =
        proxy(HttpResponseReceived::class.java) { method, args ->
            when (method) {
                "headers" -> headers
                "headerValue" -> headers.firstOrNull { it.name().equals(args!![0] as String, true) }?.value()
                "bodyToString" -> body
                "withBody" -> response(headers, args!![0] as String)
                "withAddedHeader" -> response(headers + header(args!![0] as String, args[1] as String), body)
                "withRemovedHeaders" -> {
                    @Suppress("UNCHECKED_CAST")
                    val removed = args!![0] as List<HttpHeader>
                    response(headers.filter { existing -> removed.none { it === existing } }, body)
                }
                "initiatingRequest" -> {
                    val type = HttpResponseReceived::class.java.getMethod("initiatingRequest").returnType
                    Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, requestMethod, _ ->
                        when (requestMethod.name) {
                            "url" -> url
                            "httpService" -> {
                                val serviceType = requestMethod.returnType
                                Proxy.newProxyInstance(serviceType.classLoader, arrayOf(serviceType)) { _, serviceMethod, _ ->
                                    if (serviceMethod.name == "host") "video.example" else error(serviceMethod.name)
                                }
                            }
                            else -> error(requestMethod.name)
                        }
                    }
                }
                else -> error("Unexpected response method: $method")
            }
        }

    private fun inject(
        policies: List<Pair<String, String>>,
        enabled: Boolean = true,
        strip: Boolean = true,
        allow: List<String> = listOf("video.example"),
        contentType: String = "text/html"
    ): HttpResponse {
        val api = api()
        val config = ConfigStore(api)
        config.config.injectionEnabled = enabled
        config.config.stripCsp = strip
        config.config.hostAllowList = allow
        val originalFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory::class.java) { method, args ->
            check(method == "responseResult") { method }
            proxy(ResponseReceivedAction::class.java) { actionMethod, _ ->
                check(actionMethod == "response") { actionMethod }
                args!![0]
            }
        }
        try {
            val headers = listOf(header("Content-Type", contentType)) + policies.map { header(it.first, it.second) }
            return InjectorHandler(api, config, ScopeGate(api)).handleHttpResponseReceived(response(headers)).response()
        } finally {
            ObjectFactoryLocator.FACTORY = originalFactory
        }
    }

    private fun HttpResponse.values(name: String) = headers().filter { it.name().equals(name, true) }.map { it.value() }

    @Test fun `allowed cross origin frame keeps CSP precedence over SAMEORIGIN`() {
        val out = inject(listOf(
            "Content-Security-Policy" to "default-src 'self'; script-src 'none'; frame-ancestors 'self' https://app.example",
            "X-Frame-Options" to "SAMEORIGIN"
        ))
        assertEquals(listOf("frame-ancestors 'self' https://app.example"), out.values("Content-Security-Policy"))
        assertEquals(listOf("SAMEORIGIN"), out.values("X-Frame-Options"))
        assertContains(out.bodyToString(), "window.__WRTC_CFG__")
        assertFalse(out.bodyToString().contains("<meta"))
    }

    @Test fun `multiple headers and policy lists retain every enforced framing restriction`() {
        val out = inject(listOf(
            "content-security-policy" to "script-src 'none'; frame-ancestors https://app.example, default-src 'none'; frame-ancestors 'self'",
            "CONTENT-SECURITY-POLICY" to "FRAME-ANCESTORS\t'none'; script-src 'none'",
            "Content-Security-Policy-Report-Only" to "frame-ancestors https://report.example",
            "content-security-policy-report-only" to "script-src 'none'"
        ))
        assertEquals(listOf("frame-ancestors https://app.example, frame-ancestors 'self'", "FRAME-ANCESTORS\t'none'"), out.values("Content-Security-Policy"))
        assertTrue(out.values("Content-Security-Policy-Report-Only").isEmpty())
    }

    @Test fun `duplicate directives retain first directive and empty ancestor lists stay restrictive`() {
        val out = inject(listOf(
            "Content-Security-Policy" to "frame-ancestors 'none'; frame-ancestors *; default-src 'self'",
            "Content-Security-Policy" to "frame-ancestors; script-src 'none'"
        ))
        assertEquals(listOf("frame-ancestors 'none'", "frame-ancestors"), out.values("Content-Security-Policy"))
    }

    @Test fun `XFO only and report only policies do not gain a permissive ancestor policy`() {
        val out = inject(listOf(
            "Content-Security-Policy" to "script-src 'self'; frame-ancestors-extra *",
            "Content-Security-Policy-Report-Only" to "frame-ancestors *",
            "X-Frame-Options" to "DENY"
        ))
        assertTrue(out.values("Content-Security-Policy").isEmpty())
        assertTrue(out.values("Content-Security-Policy-Report-Only").isEmpty())
        assertEquals(listOf("DENY"), out.values("X-Frame-Options"))
    }

    @Test fun `CSP stripping disabled leaves header and meta policies intact`() {
        val policy = "script-src 'self'; frame-ancestors https://app.example"
        val out = inject(listOf("Content-Security-Policy" to policy), strip = false)
        assertEquals(listOf(policy), out.values("Content-Security-Policy"))
        assertContains(out.bodyToString(), "<meta")
        assertContains(out.bodyToString(), "window.__WRTC_CFG__")
    }

    @Test fun `disabled injection out of scope unlisted hosts and non HTML stay untouched`() {
        val policy = "script-src 'none'; frame-ancestors https://app.example"
        val headers = listOf("Content-Security-Policy" to policy)
        val outputs = mutableListOf(
            inject(headers, enabled = false),
            inject(headers, allow = listOf("other.example")),
            inject(headers, contentType = "application/json")
        )
        inScope = false
        outputs += inject(headers)
        for (out in outputs) {
            assertEquals(listOf(policy), out.values("Content-Security-Policy"))
            assertEquals(html, out.bodyToString())
        }
    }
}
