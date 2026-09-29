package webrtc.bridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import webrtc.config.ConfigStore
import webrtc.config.SdpMutationConfig
import webrtc.config.WebRtcConfig
import webrtc.config.DataChannelFuzzConfig
import webrtc.telemetry.TelemetryTableModel
import webrtc.scope.ScopeGate
import java.lang.reflect.Proxy
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLEncoder
import java.util.Collections
import javax.swing.SwingUtilities
import kotlin.test.*

class BridgeServerTest {
    private val errors = Collections.synchronizedList(mutableListOf<String>())
    private var inScope = true
    private var persisted: String? = null

    private fun api(): MontoyaApi {
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "logToError" -> { errors.add(args?.first().toString()); null }
                method.name == "isInScope" -> inScope
                method.name == "getString" -> persisted
                method.name == "setString" -> { persisted = args!![1] as String; null }
                method.returnType == String::class.java -> null
                method.returnType.isInterface -> proxy(method.returnType)
                else -> null
            }
        }
        return proxy(MontoyaApi::class.java) as MontoyaApi
    }

    private fun exchange(port: Int, request: String): String = Socket("127.0.0.1", port).use {
        it.soTimeout = 3_000
        it.getOutputStream().write(request.toByteArray(Charsets.UTF_8))
        it.shutdownOutput()
        it.getInputStream().readBytes().toString(Charsets.UTF_8)
    }

    private fun withBridge(block: (BridgeServer, Int, TelemetryTableModel, ConfigStore) -> Unit) {
        val api = api()
        val config = ConfigStore(api)
        val port = ServerSocket(0).use { it.localPort }
        config.config.bridgePort = port
        config.config.collectPath = "/events"
        config.config.commandPath = "/poll"
        val telemetry = TelemetryTableModel()
        val bridge = BridgeServer(api, config, telemetry)
        try {
            bridge.start()
            assertTrue(errors.isEmpty(), errors.toString())
            block(bridge, port, telemetry, config)
            assertTrue(errors.isEmpty(), errors.toString())
        } finally {
            bridge.stop()
        }
    }

    @Test fun `bridge runs without jdk httpserver and serves configured command path`() {
        assertFalse(ModuleLayer.boot().findModule("jdk.httpserver").isPresent)
        withBridge { _, port, _, _ ->
            val response = exchange(port, "GET /poll?cache=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            assertTrue(response.startsWith("HTTP/1.1 200 OK\r\n"))
            assertContains(response, "Access-Control-Allow-Origin: *\r\n")
            assertContains(response, "Content-Type: application/json")
            val body = response.substringAfter("\r\n\r\n")
            assertContains(response, "Content-Length: ${body.toByteArray().size}\r\n")
            val doc = Json.parseToJsonElement(body).jsonObject
            assertEquals("true", doc["ok"]?.jsonPrimitive?.content)
            assertEquals("/events", doc["bridge"]?.jsonObject?.get("collect")?.jsonPrimitive?.content)
            assertEquals("[]", doc["commands"].toString())
        }
    }

    @Test fun `collect accepts UTF8 single events and chunked batches`() {
        withBridge { _, port, telemetry, _ ->
            val body = """{"type":"ice","candidate":"192.168.1.2 café"}"""
            val response = exchange(port, "POST /events HTTP/1.1\r\nHost: localhost\r\ncontent-length: ${body.toByteArray().size}\r\n\r\n$body")
            assertTrue(response.startsWith("HTTP/1.1 204 No Content\r\n"))
            assertFalse(response.contains("Content-Length:"))
            assertEquals("", response.substringAfter("\r\n\r\n"))
            val batch = """[{"type":"installed","detail":"ready"},{"type":"dc-send","bytes":12}]"""
            val chunks = batch.chunked(19).joinToString("") { "${it.toByteArray().size.toString(16)};test=yes\r\n$it\r\n" }
            assertTrue(exchange(port, "POST /events HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n${chunks}0\r\nX-Trailer: done\r\n\r\n").startsWith("HTTP/1.1 204"))
            SwingUtilities.invokeAndWait {
                assertEquals(3, telemetry.rowCount)
                assertEquals("192.168.1.2 café", telemetry.eventAt(0)?.summary)
                assertEquals(true, telemetry.eventAt(0)?.private)
                assertEquals("installed", telemetry.eventAt(1)?.type)
                assertEquals("dc-send", telemetry.eventAt(2)?.type)
            }
        }
    }

    @Test fun `preflight and unknown routes do not collect events`() {
        withBridge { _, port, telemetry, _ ->
            for (path in listOf("/events", "/poll")) {
                val response = exchange(port, "OPTIONS $path HTTP/1.1\r\nOrigin: https://example.test\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 204"))
                assertContains(response, "Access-Control-Allow-Methods: GET, POST, OPTIONS")
                assertContains(response, "Access-Control-Allow-Headers: Content-Type")
            }
            assertTrue(exchange(port, "GET /missing HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 404"))
            assertTrue(exchange(port, "POST /events HTTP/1.1\r\nContent-Length: 3\r\n\r\n???").startsWith("HTTP/1.1 204"))
            SwingUtilities.invokeAndWait { assertEquals(0, telemetry.rowCount) }
        }
    }

    @Test fun `malformed truncated and oversized requests are rejected and server remains usable`() {
        withBridge { _, port, _, _ ->
            val requests = listOf(
                "broken\r\n\r\n" to 400,
                "POST /events HTTP/1.1\r\nContent-Length: -1\r\n\r\n" to 400,
                "POST /events HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n" to 400,
                "POST /events HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" to 400,
                "POST /events HTTP/1.1\r\nContent-Length: 4\r\n\r\nx" to 400,
                "POST /events HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n" to 413,
                "POST /events HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n" to 413,
                "POST /events HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n" to 501,
                "GET /poll HTTP/1.1\r\nX-Large: ${"a".repeat(33 * 1024)}\r\n\r\n" to 431
            )
            for ((request, code) in requests) {
                assertTrue(exchange(port, request).startsWith("HTTP/1.1 $code"), "Expected $code for ${request.take(80)}")
            }
            assertTrue(exchange(port, "GET /poll HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 200"))
        }
    }

    @Test fun `expect continue is sent before waiting for the body`() {
        withBridge { _, port, _, _ ->
            Socket("127.0.0.1", port).use { socket ->
                socket.soTimeout = 3_000
                socket.getOutputStream().write("POST /events HTTP/1.1\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n".toByteArray())
                val interim = socket.getInputStream().readNBytes(25).toString(Charsets.US_ASCII)
                assertEquals("HTTP/1.1 100 Continue\r\n\r\n", interim)
                socket.getOutputStream().write("{}".toByteArray())
                assertTrue(socket.getInputStream().readBytes().toString(Charsets.UTF_8).startsWith("HTTP/1.1 204"))
            }
        }
    }

    @Test fun `restart rebinds and stop closes idle clients and releases port`() {
        withBridge { bridge, port, _, _ ->
            bridge.restart()
            assertTrue(exchange(port, "GET /poll HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 200"))
            Socket("127.0.0.1", port).use { idle ->
                idle.soTimeout = 3_000
                idle.getOutputStream().write("GET /".toByteArray())
                // A subsequent completed request ensures the listener has accepted the idle client.
                exchange(port, "GET /poll HTTP/1.1\r\n\r\n")
                bridge.stop()
                val closed = runCatching { idle.getInputStream().read() }.fold(
                    onSuccess = { it == -1 }, onFailure = { it is java.net.SocketException }
                )
                assertTrue(closed)
            }
            ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress("127.0.0.1", port)) }
            bridge.start()
            assertTrue(exchange(port, "GET /poll HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 200"))
        }
    }

    @Test fun `bind failure is logged and can be recovered`() {
        val api = api()
        val config = ConfigStore(api)
        val bridge = BridgeServer(api, config, TelemetryTableModel())
        try {
            ServerSocket(0).use {
                config.config.bridgePort = it.localPort
                bridge.start()
                assertTrue(errors.single().startsWith("[bridge] failed to start"))
            }
            errors.clear()
            bridge.start()
            assertTrue(exchange(config.config.bridgePort, "GET /command HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 200"))
            assertTrue(errors.isEmpty())
        } finally {
            bridge.stop()
        }
    }

    @Test fun `mutation commands require enabled injection allowed host and current scope`() {
        withBridge { _, port, _, config ->
            config.save(config.config.copy(
                injectionEnabled = true, hostAllowList = listOf("example.test"),
                sdpMutation = SdpMutationConfig(enabled = true, removeFingerprint = true)
            ))
            fun commands(frame: String? = "https://example.test/call?room=a&user=b"): String {
                val query = frame?.let { "?frame=" + URLEncoder.encode(it, Charsets.UTF_8) }.orEmpty()
                val response = exchange(port, "GET /poll$query HTTP/1.1\r\n\r\n")
                assertContains(response, "Cache-Control: no-store")
                return Json.parseToJsonElement(response.substringAfter("\r\n\r\n")).jsonObject["commands"].toString()
            }
            val active = commands()
            assertContains(active, "sdp-mutation")
            assertContains(active, "\"target\":\"remote\"") // Default fields must reach the agent.
            assertContains(active, "\"removeFingerprint\":true")
            assertEquals("[]", commands(null))
            assertEquals("[]", commands("https://example.test.evil.test/call"))
            assertEquals("[]", commands("https://evil.test/call"))
            assertEquals("[]", commands("file:///call"))
            assertEquals("[]", commands("https://name@example.test/call"))
            assertEquals("[]", commands("not a URL"))
            inScope = false
            assertEquals("[]", commands())
            inScope = true
            config.save(config.config.copy(injectionEnabled = false))
            assertEquals("[]", commands())
            config.save(config.config.copy(injectionEnabled = true, sdpMutation = config.config.sdpMutation.copy(enabled = false)))
            assertEquals("[]", commands())
        }
    }

    @Test fun `mutation settings persist and old project configs default to disabled`() {
        assertFalse(Json.decodeFromString<WebRtcConfig>("{}").sdpMutation.enabled)
        val api = api()
        val config = ConfigStore(api)
        val rules = SdpMutationConfig(enabled = true, target = "both", pcId = "pc2", find = "a=sendrecv", replacement = "a=inactive")
        config.save(config.config.copy(sdpMutation = rules))
        assertEquals(rules, ConfigStore(api).config.sdpMutation)
        // M0 saves use a copy so editing unrelated settings retains M3.
        config.save(config.config.copy(bridgePort = 9999))
        assertEquals(rules, ConfigStore(api).config.sdpMutation)
        assertFailsWith<IllegalArgumentException> { SdpMutationConfig(enabled = true) }
        assertFailsWith<IllegalArgumentException> { SdpMutationConfig(target = "bad") }
    }

    @Test fun `active command delivery authorization and cancellation work through socket bridge`() {
        val api = api()
        val config = ConfigStore(api)
        val port = ServerSocket(0).use { it.localPort }
        config.save(config.config.copy(bridgePort = port, injectionEnabled = true, hostAllowList = listOf("example.test")))
        val telemetry = TelemetryTableModel()
        val controller = ActiveTestController(config, ScopeGate(api)::inScope, telemetry)
        val bridge = BridgeServer(api, config, telemetry, controller)
        try {
            bridge.start()
            val body = """{"type":"agent-state","agent":"page-a","frame":"https://example.test/call","channels":[{"channelId":"dc1","pc":"pc1","label":"test","state":"open"}]}"""
            assertTrue(exchange(port, "POST /collect HTTP/1.1\r\nContent-Length: ${body.toByteArray().size}\r\n\r\n$body").startsWith("HTTP/1.1 204"))
            val id = controller.queueFuzz("page-a", "dc1", DataChannelFuzzConfig())
            val frame = URLEncoder.encode("https://example.test/call", Charsets.UTF_8)
            fun get(query: String) = Json.parseToJsonElement(exchange(port, "GET /command?frame=$frame&$query HTTP/1.1\r\n\r\n").substringAfter("\r\n\r\n")).jsonObject
            assertEquals("[]", get("agent=other&poll=1")["commands"].toString())
            assertContains(get("agent=page-a&poll=1")["commands"].toString(), "dc-fuzz")
            assertEquals("true", get("agent=page-a&authorize=$id")["authorized"]?.jsonPrimitive?.content)
            assertEquals("[]", get("agent=page-a&poll=1")["commands"].toString())
            assertTrue(controller.cancelJob(id))
            assertEquals("false", get("agent=page-a&authorize=$id")["authorized"]?.jsonPrimitive?.content)
            assertFalse(controller.cancelJob(id))
            assertTrue(errors.isEmpty(), errors.toString())
        } finally { bridge.stop() }
    }
}
