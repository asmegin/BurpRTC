package webrtc.authz

import burp.api.montoya.core.ToolSource
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import webrtc.inject.InjectorHandler
import webrtc.workflow.RequestCatalog
import java.lang.reflect.Proxy
import kotlin.test.*

class HttpSessionCaptureTest {
    private fun <T> proxy(type: Class<T>, block: (String, Array<out Any?>?) -> Any?): T = type.cast(
        Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, m, args -> block(m.name, args) })
    private fun source(tool: ToolType) = proxy(ToolSource::class.java) { name, args -> when (name) {
        "toolType" -> tool
        "isFromTool" -> (args!![0] as Array<*>).contains(tool)
        else -> error(name)
    } }
    private fun outgoing(req: HttpRequest, tool: ToolType): HttpRequestToBeSent = HttpRequestToBeSent::class.java.cast(
        Proxy.newProxyInstance(HttpRequestToBeSent::class.java.classLoader, arrayOf(HttpRequestToBeSent::class.java)) { _, m, args ->
            if (m.name == "toolSource") source(tool) else HttpRequest::class.java.getMethod(m.name, *m.parameterTypes).invoke(req, *args.orEmpty())
        })
    private fun incoming(req: HttpRequest, tool: ToolType) = proxy(HttpResponseReceived::class.java) { name, _ -> when (name) {
        "toolSource" -> source(tool)
        "initiatingRequest" -> req
        "headerValue" -> "application/json"
        "statusCode" -> 200.toShort()
        else -> error(name)
    } }
    @Test fun `HTTP handler captures browser sessions without injection and ignores extension replays`() {
        val f = AuthzFixture(); f.config.save(f.config.config.copy(injectionEnabled = false))
        val requests = RequestCatalog()
        val handler = InjectorHandler(f.api, f.config, f.scope, requests, sessions = f.catalog)
        val original = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory::class.java) { name, args -> when (name) {
            "requestResult" -> proxy(RequestToBeSentAction::class.java) { method, _ -> if (method == "request") args!![0] else null }
            "responseResult" -> proxy(ResponseReceivedAction::class.java) { method, _ -> if (method == "response") args!![0] else null }
            else -> error(name)
        } }
        try {
            val alice = request(headers = mapOf("Cookie" to "sid=alice"))
            val bob = request(headers = mapOf("Cookie" to "sid=bob"))
            handler.handleHttpRequestToBeSent(outgoing(alice, ToolType.PROXY))
            handler.handleHttpResponseReceived(incoming(alice, ToolType.PROXY))
            handler.handleHttpRequestToBeSent(outgoing(bob, ToolType.EXTENSIONS))
            handler.handleHttpResponseReceived(incoming(bob, ToolType.EXTENSIONS))
            assertEquals(1, f.catalog.snapshot().size)
            assertEquals("sid=alice", f.catalog.snapshot().single().identity.headers["Cookie"])
            assertEquals("sid=alice", requests.recent().single().headerValue("Cookie"))
            f.inScope = false
            handler.handleHttpRequestToBeSent(outgoing(bob, ToolType.PROXY))
            handler.handleHttpResponseReceived(incoming(bob, ToolType.PROXY))
            assertEquals(1, f.catalog.snapshot().size)
            assertEquals(0, f.sent.size)
        } finally { ObjectFactoryLocator.FACTORY = original }
    }
}
