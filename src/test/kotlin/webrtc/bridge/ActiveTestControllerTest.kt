package webrtc.bridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*
import webrtc.config.*
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import javax.swing.SwingUtilities
import kotlin.test.*

class ActiveTestControllerTest {
    private val frame = "https://example.test/call"
    private val scopes = mutableSetOf(frame)
    private var clock = 1000L
    private var persisted: String? = null
    private fun api(): MontoyaApi {
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "getString" -> persisted
                method.name == "setString" -> { persisted = args!![1] as String; null }
                method.returnType.isInterface -> proxy(method.returnType)
                else -> null
            }
        }
        return proxy(MontoyaApi::class.java) as MontoyaApi
    }
    private val api = api()
    private val store = ConfigStore(api).also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
    private val telemetry = TelemetryTableModel()
    private val controller = ActiveTestController(store, scopes::contains, telemetry) { clock }

    private fun heartbeat(agent: String = "agent-a", state: String = "open", completed: JsonArray = JsonArray(emptyList())) {
        controller.observe(buildJsonObject {
            put("type", "agent-state"); put("agent", agent); put("frame", frame)
            put("channels", buildJsonArray { add(buildJsonObject {
                put("channelId", "dc1"); put("pc", "pc1"); put("label", "same-label"); put("state", state)
            }) }); put("completed", completed)
        })
    }

    @Test fun `commands target one page instance and channel and are not redelivered after claim`() {
        heartbeat(); heartbeat("agent-b")
        val id = controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig())
        assertEquals(1, controller.commands("agent-a", frame).size)
        assertEquals(0, controller.commands("agent-b", frame).size)
        assertEquals(0, controller.commands("agent-a", "https://example.test/elsewhere").size)
        assertFalse(controller.authorize("agent-b", frame, id))
        assertTrue(controller.authorize("agent-a", frame, id))
        assertTrue(controller.commands("agent-a", frame).isEmpty())
        assertTrue(controller.authorize("agent-a", frame, id))
        assertFailsWith<IllegalArgumentException> { controller.queueIce("agent-a", IceProbeConfig()) }
    }

    @Test fun `sdp fuzz enqueues a command and validates settings`() {
        heartbeat()
        val id = controller.queueSdpFuzz("agent-a", SdpFuzzConfig())
        val cmds = controller.commands("agent-a", frame)
        assertEquals(1, cmds.size)
        assertEquals("sdp-fuzz", (cmds[0]["type"] as JsonPrimitive).content)
        assertFailsWith<IllegalArgumentException> { controller.queueSdpFuzz("agent-a", SdpFuzzConfig(descriptionType = "bogus")) }
        assertFailsWith<IllegalArgumentException> { controller.queueSdpFuzz("agent-a", SdpFuzzConfig(maxCases = 0)) }
    }

    @Test fun `scope revocation disabling injection and stop revoke running commands`() {
        heartbeat()
        var id = controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig())
        assertTrue(controller.authorize("agent-a", frame, id))
        scopes.clear()
        assertFalse(controller.authorize("agent-a", frame, id))
        scopes.add(frame)
        id = controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig())
        store.save(store.config.copy(injectionEnabled = false))
        assertFalse(controller.authorize("agent-a", frame, id))
        store.save(store.config.copy(injectionEnabled = true))
        id = controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig())
        controller.cancel("agent-a", "dc-fuzz")
        assertFalse(controller.authorize("agent-a", frame, id))
        id = controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig())
        controller.cancelAll()
        assertFalse(controller.authorize("agent-a", frame, id))
    }

    @Test fun `ICE requires endpoint scope on queue delivery and lease renewal`() {
        heartbeat()
        val settings = IceProbeConfig("turns:relay.example.test:5349?transport=tcp", "test-user", "super-secret", "relay")
        val endpoint = "https://relay.example.test:5349/"
        assertFailsWith<IllegalArgumentException> { controller.queueIce("agent-a", settings) }
        scopes.add(endpoint)
        var id = controller.queueIce("agent-a", settings)
        scopes.remove(endpoint)
        assertTrue(controller.commands("agent-a", frame).isEmpty())
        assertFalse(controller.authorize("agent-a", frame, id))
        scopes.add(endpoint)
        id = controller.queueIce("agent-a", settings)
        assertTrue(controller.authorize("agent-a", frame, id))
        scopes.remove(endpoint)
        assertFalse(controller.authorize("agent-a", frame, id))
        SwingUtilities.invokeAndWait {
            for (index in 0 until telemetry.rowCount) {
                assertFalse(telemetry.eventAt(index)!!.raw.contains("super-secret"))
                assertFalse(telemetry.eventAt(index)!!.raw.contains("test-user"))
            }
        }
    }

    @Test fun `expired or stale pages cannot start and closed channels cannot receive a run`() {
        heartbeat(state = "closed")
        assertFailsWith<IllegalArgumentException> { controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig()) }
        heartbeat()
        val id = controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig())
        clock += 90001
        assertFalse(controller.authorize("agent-a", frame, id))
        assertTrue(controller.agents().isEmpty())
        assertFailsWith<IllegalArgumentException> { controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig()) }
    }

    @Test fun `completion heartbeat releases page for next test and wrong agent cannot finish it`() {
        heartbeat(); heartbeat("agent-b")
        val id = controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig())
        controller.authorize("agent-a", frame, id)
        val result = buildJsonArray { add(buildJsonObject { put("commandId", id); put("status", "completed") }) }
        heartbeat("agent-b", completed = result)
        assertFailsWith<IllegalArgumentException> { controller.queueFuzz("agent-a", "dc1", DataChannelFuzzConfig()) }
        heartbeat(completed = result)
        assertFalse(controller.authorize("agent-a", frame, id))
        assertTrue(controller.queueIce("agent-a", IceProbeConfig()).isNotEmpty())
    }

    @Test fun `ICE URI validation maps exact host port and secure scheme for scope`() {
        assertEquals("http://stun.example.test:3478/", IceEndpoint.parse("stun:stun.example.test").scopeUrl)
        assertEquals("https://relay.example.test:5349/", IceEndpoint.parse("turns:relay.example.test?transport=tcp").scopeUrl)
        assertEquals("http://[::1]:3479/", IceEndpoint.parse("turn:[::1]:3479?transport=udp").scopeUrl)
        for (invalid in listOf("https://example.test", "stun:host:0", "turn:user:pass@host", "turn:host/path", "turn:host?transport=udp&other=1", "stun:host?transport=udp", "turn:[invalid]:3478")) {
            assertFailsWith<IllegalArgumentException>(invalid) { IceEndpoint.parse(invalid) }
        }
        assertFailsWith<IllegalArgumentException> { IceProbeConfig("turn:host", policy = "relay").validate() }
        assertFailsWith<IllegalArgumentException> { IceProbeConfig(policy = "relay").validate() }
    }

    @Test fun `fuzz limits account for UTF8 bytes hex validity and run totals`() {
        DataChannelFuzzConfig(payload = "é", maxBytes = 2).validate()
        assertFailsWith<IllegalArgumentException> { DataChannelFuzzConfig(payload = "é", maxBytes = 1).validate() }
        DataChannelFuzzConfig(mode = "hex", payload = "00 ff 12", maxBytes = 3).validate()
        assertFailsWith<IllegalArgumentException> { DataChannelFuzzConfig(mode = "hex", payload = "f").validate() }
        assertFailsWith<IllegalArgumentException> { DataChannelFuzzConfig(count = 50, maxBytes = 65536).validate() }
        assertFailsWith<IllegalArgumentException> { DataChannelFuzzConfig(intervalMs = 0).validate() }
    }

    @Test fun `T1 stats capture and T8 opt-in flood enqueue bounded commands`() {
        heartbeat()
        val capture = controller.queueCaptureStats("agent-a")
        val captureCmd = controller.commands("agent-a", frame).firstOrNull()
        assertEquals("capture-stats", (captureCmd!!["type"] as JsonPrimitive).content)
        assertTrue(controller.authorize("agent-a", frame, capture))
        controller.cancelJob(capture)

        assertFailsWith<IllegalArgumentException> { SignalingFloodConfig(confirm = false).validate() }
        assertFailsWith<IllegalArgumentException> { SignalingFloodConfig(confirm = true, count = 0).validate() }
        assertFailsWith<IllegalArgumentException> { SignalingFloodConfig(confirm = true, intervalMs = 100).validate() }
        val flood = controller.queueSignalingFlood("agent-a", SignalingFloodConfig(confirm = true, count = 3, intervalMs = 500))
        val floodCmd = controller.commands("agent-a", frame).firstOrNull()
        assertEquals("signaling-flood", (floodCmd!!["type"] as JsonPrimitive).content)
        assertEquals(true, ((floodCmd["config"] as JsonObject)["confirm"] as JsonPrimitive).boolean)
        assertTrue(controller.authorize("agent-a", frame, flood))
    }

    @Test fun `M4 M6 settings roundtrip without restarting active tests`() {
        val fuzz = DataChannelFuzzConfig(mode = "boundary", count = 5)
        val ice = IceProbeConfig("turn:relay.example.test", "user", "credential", "relay")
        store.save(store.config.copy(dataChannelFuzz = fuzz, iceProbe = ice))
        val restored = ConfigStore(api).config
        assertEquals(fuzz, restored.dataChannelFuzz)
        assertEquals(ice, restored.iceProbe)
        assertTrue(ActiveTestController(store, scopes::contains, telemetry).agents().isEmpty())
        val old = Json.decodeFromString<WebRtcConfig>("{}")
        assertEquals(DataChannelFuzzConfig(), old.dataChannelFuzz)
        assertEquals(IceProbeConfig(), old.iceProbe)
    }

    @Test fun `next open fuzz is opt in one shot and only accepts an open channel`() {
        heartbeat()
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        val settings = DataChannelFuzzConfig(payload = "automatic", count = 2)
        controller.armNextOpenFuzz(settings)
        heartbeat(state = "connecting")
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        heartbeat(state = "closed")
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        assertTrue(controller.nextOpenFuzzArmed())
        heartbeat()
        val id = controller.queueNextOpenFuzz("agent-a", frame, "dc1")!!
        assertFalse(controller.nextOpenFuzzArmed())
        assertEquals(id, controller.automaticFuzzJob())
        assertEquals("automatic", controller.commands("agent-a", frame).single()["config"]!!.jsonObject["payload"]!!.jsonPrimitive.content)
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        assertEquals(1, controller.commands("agent-a", frame).size)
        assertFalse(ActiveTestController(store, scopes::contains, telemetry).nextOpenFuzzArmed())
    }

    @Test fun `automatic fuzz checks agent frame freshness scope allow list and injection`() {
        heartbeat(); controller.armNextOpenFuzz(DataChannelFuzzConfig())
        assertNull(controller.queueNextOpenFuzz("other", frame, "dc1"))
        assertNull(controller.queueNextOpenFuzz("agent-a", "https://example.test/elsewhere", "dc1"))
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "unknown"))
        scopes.clear()
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        scopes.add(frame)
        store.save(store.config.copy(hostAllowList = listOf("other.test")))
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        store.save(store.config.copy(hostAllowList = listOf("example.test"), injectionEnabled = false))
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        store.save(store.config.copy(injectionEnabled = true))
        clock += 15001
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        assertTrue(controller.nextOpenFuzzArmed())
        heartbeat()
        val id = controller.queueNextOpenFuzz("agent-a", frame, "dc1")!!
        scopes.clear()
        assertFalse(controller.authorize("agent-a", frame, id))
    }

    @Test fun `busy page keeps automatic arm and disarming cancels automatic jobs`() {
        heartbeat(); controller.armNextOpenFuzz(DataChannelFuzzConfig())
        val manual = controller.queueCaptureStats("agent-a")
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
        assertTrue(controller.nextOpenFuzzArmed())
        controller.cancelJob(manual)
        val id = controller.queueNextOpenFuzz("agent-a", frame, "dc1")!!
        assertTrue(controller.authorize("agent-a", frame, id))
        controller.disarmNextOpenFuzz()
        assertFalse(controller.authorize("agent-a", frame, id))
        controller.armNextOpenFuzz(DataChannelFuzzConfig())
        controller.cancelAll()
        assertFalse(controller.nextOpenFuzzArmed())
        assertNull(controller.queueNextOpenFuzz("agent-a", frame, "dc1"))
    }

    @Test fun `automatic arming validates caps and is never persisted`() {
        assertFailsWith<IllegalArgumentException> { controller.armNextOpenFuzz(DataChannelFuzzConfig(count = 50, maxBytes = 65536)) }
        controller.armNextOpenFuzz(DataChannelFuzzConfig())
        assertFalse(ActiveTestController(ConfigStore(api), scopes::contains, telemetry).nextOpenFuzzArmed())
        store.save(store.config.copy(injectionEnabled = false))
        assertFailsWith<IllegalArgumentException> { controller.armNextOpenFuzz(DataChannelFuzzConfig()) }
    }
}
