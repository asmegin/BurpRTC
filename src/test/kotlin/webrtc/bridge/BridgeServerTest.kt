package webrtc.bridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*
import webrtc.config.*
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URLEncoder
import kotlin.test.*

class BridgeServerTest {
    private val frame = "https://example.test/call"
    private var scoped = true
    private val errors = mutableListOf<String>()
    private fun api(): MontoyaApi {
        fun stub(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "isInScope" -> scoped
                method.name == "logToError" -> { errors += args?.first().toString(); null }
                method.name == "getString" -> null
                method.returnType.isInterface -> stub(method.returnType)
                else -> null
            }
        }
        return stub(MontoyaApi::class.java) as MontoyaApi
    }
    private fun exchange(port: Int, request: String) = Socket("127.0.0.1", port).use {
        it.soTimeout = 3000; it.getOutputStream().write(request.toByteArray()); it.shutdownOutput()
        it.getInputStream().readBytes().toString(Charsets.UTF_8)
    }
    private class Fixture(val bridge: BridgeServer, val config: ConfigStore, val telemetry: TelemetryTableModel,
                          val controller: ActiveTestController, val port: Int, var token: String)
    private fun fixture(block: (Fixture) -> Unit) {
        val api = api(); val config = ConfigStore(api); val port = ServerSocket(0).use { it.localPort }
        config.save(config.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"), bridgePort = port,
            sdpMutation = SdpMutationConfig(enabled = true, removeFingerprint = true)))
        val telemetry = TelemetryTableModel(); val controller = ActiveTestController(config, { scoped }, telemetry)
        val bridge = BridgeServer(api, config, telemetry, controller)
        try {
            bridge.start()
            block(Fixture(bridge, config, telemetry, controller, port, config.bridgeSessions.issue(frame)))
            assertTrue(errors.isEmpty(), errors.toString())
        } finally { bridge.stop() }
    }
    private fun request(f: Fixture, method: String = "GET", path: String = "/command", body: String = "",
                        frame: String = this.frame, agent: String = "agent-test", token: String = f.token,
                        host: String = "127.0.0.1:${f.port}", origin: String = "https://example.test", extra: String = ""): String {
        val query = "session=$token&frame=${URLEncoder.encode(frame, Charsets.UTF_8)}&agent=$agent$extra"
        return exchange(f.port, "$method $path?$query HTTP/1.1\r\nHost: $host\r\nOrigin: $origin\r\nContent-Length: ${body.toByteArray().size}\r\n\r\n$body")
    }
    private fun event(type: String, frame: String = this.frame, agent: String = "agent-test") =
        buildJsonObject { put("type", type); put("frame", frame); put("agent", agent); put("candidate", "candidate:1 1 udp 1 192.168.1.2 5000 typ host") }.toString()

    @Test fun `bridge operates without optional module and authenticates commands`() = fixture { f ->
        assertFalse(ModuleLayer.boot().findModule("jdk.httpserver").isPresent)
        val response = request(f)
        assertTrue(response.startsWith("HTTP/1.1 200"))
        assertContains(response, "Cache-Control: no-store")
        assertContains(response, "sdp-mutation")
    }
    @Test fun `Host Origin token frame and agent all bind command access`() = fixture { f ->
        assertTrue(request(f).startsWith("HTTP/1.1 200"))
        for (response in listOf(request(f, token = "guess"), request(f, host = "rebind.attacker.test"), request(f, origin = "https://attacker.test"),
            request(f, frame = "https://example.test/other"), request(f, agent = "another-agent")))
            assertTrue(response.startsWith("HTTP/1.1 403"), response)
    }
    @Test fun `valid telemetry accepted and malformed fields cannot crash bridge`() = fixture { f ->
        assertTrue(request(f, "POST", "/collect", event("ice")).startsWith("HTTP/1.1 204"))
        assertEquals(1, f.telemetry.snapshot().size)
        val malformed = buildJsonObject { put("type", buildJsonObject {}); put("private", buildJsonArray {}); put("frame", frame); put("agent", "agent-test") }.toString()
        assertTrue(request(f, "POST", "/collect", malformed).startsWith("HTTP/1.1 204"))
        assertTrue(request(f).startsWith("HTTP/1.1 200"))
    }
    @Test fun `untrusted and cross-page events never enter telemetry or command state`() = fixture { f ->
        assertTrue(request(f, "POST", "/collect", event("ice", "https://other.test/")).startsWith("HTTP/1.1 403"))
        assertTrue(request(f, "POST", "/collect", event("ice"), token = "unknown").startsWith("HTTP/1.1 403"))
        assertTrue(f.telemetry.snapshot().isEmpty())
    }
    @Test fun `revoking scope and injection stops commands and collection`() = fixture { f ->
        scoped = false
        val doc = Json.parseToJsonElement(request(f).substringAfter("\r\n\r\n")).jsonObject
        assertTrue(doc["commands"]!!.jsonArray.isEmpty())
        assertTrue(request(f, "POST", "/collect", event("ice")).startsWith("HTTP/1.1 403"))
        scoped = true; f.config.save(f.config.config.copy(injectionEnabled = false))
        assertTrue(Json.parseToJsonElement(request(f).substringAfter("\r\n\r\n")).jsonObject["commands"]!!.jsonArray.isEmpty())
    }
    @Test fun `restart invalidates previous page capabilities and releases socket`() = fixture { f ->
        val old = f.token; f.bridge.restart()
        assertTrue(request(f, token = old).startsWith("HTTP/1.1 403"))
        f.token = f.config.bridgeSessions.issue(frame)
        assertTrue(request(f).startsWith("HTTP/1.1 200"))
    }
    @Test fun `authorized chunked UTF8 batches and preflight work`() = fixture { f ->
        val batch = "[${event("installed")},${event("ice")}]"
        val wire = "POST /collect?session=${f.token} HTTP/1.1\r\nHost: 127.0.0.1:${f.port}\r\nOrigin: https://example.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "${batch.toByteArray().size.toString(16)}\r\n$batch\r\n0\r\n\r\n"
        assertTrue(exchange(f.port, wire).startsWith("HTTP/1.1 204"))
        assertEquals(2, f.telemetry.snapshot().size)
        assertTrue(request(f, "OPTIONS").startsWith("HTTP/1.1 204"))
    }
    @Test fun `bounds reject deep batches and request smuggling`() = fixture { f ->
        assertTrue(request(f, "POST", "/collect", "[".repeat(40) + "0" + "]".repeat(40)).startsWith("HTTP/1.1 403"))
        for ((headers, code) in listOf("Content-Length: -1" to 400, "Content-Length: 1048577" to 413,
            "Content-Length: 0\r\nTransfer-Encoding: chunked" to 400, "Host: a\r\nHost: b" to 400,
            "Origin: a\r\nOrigin: b" to 400, "X-Large: ${"x".repeat(33000)}" to 431)) {
            assertTrue(exchange(f.port, "POST /collect HTTP/1.1\r\n$headers\r\n\r\n").startsWith("HTTP/1.1 $code"))
        }
    }
    @Test fun `jobs remain isolated after a second page learns another agent ID`() = fixture { f ->
        f.controller.observe(buildJsonObject { put("type", "agent-state"); put("agent", "agent-test"); put("frame", frame) })
        val id = f.controller.queueCaptureStats("agent-test")
        val other = f.config.bridgeSessions.issue("https://example.test/other")
        assertTrue(request(f, token = other, frame = "https://example.test/other", agent = "second", extra = "&authorize=$id").contains("\"authorized\":false"))
        assertTrue(request(f, extra = "&poll=1").contains(id))
        assertTrue(request(f, extra = "&authorize=$id").contains("\"authorized\":true"))
        f.controller.cancelJob(id)
        assertTrue(request(f, extra = "&authorize=$id").contains("\"authorized\":false"))
    }
}
