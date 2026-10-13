package webrtc.protocol

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*
import webrtc.assessment.*
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.test.*

class ProtocolRunnerTest {
    private val persisted = mutableMapOf<String, String>()
    private fun api(): MontoyaApi {
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "getString" -> persisted[args!![0] as String]
                method.name == "setString" -> { persisted[args!![0] as String] = args[1] as String; null }
                method.returnType.isInterface -> proxy(method.returnType)
                else -> null
            }
        }
        return proxy(MontoyaApi::class.java) as MontoyaApi
    }
    private val api = api()
    private val config = ConfigStore(api).also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("127.0.0.1"))) }
    private val telemetry = TelemetryTableModel()
    private val outcomes = OutcomeStore(api, telemetry) { config.config.assessment.engagementId }

    @Test fun `out of scope listener blocks before any packet is sent`() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { socket ->
            socket.soTimeout = 300
            ProtocolRunner(config, NetworkAuthorization(config) { false }, outcomes).use { runner ->
                val outcome = runner.run("TRN-01", ProtocolTarget.parse("stun:127.0.0.1:${socket.localPort}"))
                assertEquals("blocked", outcome.execution)
            }
            assertFails { socket.receive(DatagramPacket(ByteArray(64), 64)) }
        }
    }

    @Test fun `STUN codec round trips long-term integrity and rejects tampering`() {
        val key = java.security.MessageDigest.getInstance("MD5").digest("alice:realm:secret".toByteArray())
        val tx = ByteArray(12) { it.toByte() }
        val packet = Stun.encode(Stun.ALLOCATE, tx, listOf(Stun.USERNAME to "alice".toByteArray()), key)
        assertEquals(true, Stun.decode(packet, tx, key).integrity)
        packet[packet.size - 1] = (packet.last().toInt() xor 1).toByte()
        assertEquals(false, Stun.decode(packet, tx, key).integrity)
        val address = InetAddress.getByName("192.0.2.7")
        assertEquals(address to 3478, Stun.decodeAddress(Stun.xorAddress(address, 3478, tx), tx))
        assertFailsWith<IllegalArgumentException> { Stun.decode(packet, ByteArray(12), key) }
    }

    @Test fun `built-in runner performs scoped STUN binding and preserves observed credential pairs`() {
        config.save(config.config.copy(protocolScan = ProtocolScanConfig(turnUsername = "fallback account", turnCredential = "fallback secret", timeoutSeconds = 15)))
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { socket ->
            socket.soTimeout = 5000
            val server = Thread {
                repeat(2) {
                    val packet = DatagramPacket(ByteArray(2048), 2048)
                    socket.receive(packet)
                    val response = packet.data.copyOf(20)
                    response[0] = 1; response[1] = 1; response[2] = 0; response[3] = 0
                    socket.send(DatagramPacket(response, response.size, packet.socketAddress))
                }
            }.apply { isDaemon = true; start() }
            val grants = mutableListOf<String>()
            ProtocolRunner(config, NetworkAuthorization(config) { grants += it; true }, outcomes).use { runner ->
                assertContains(runner.check(), "no external runtime")
                val target = ProtocolTarget.parse("stun:127.0.0.1:${socket.localPort}")
                val secret = " full secret $ with whitespace \n"
                val result = runner.run("TRN-01", target, username = "observed account", password = secret)
                assertEquals("completed", result.execution, result.limitations.joinToString())
                assertEquals("built-in-turn", result.backend)
                val evidence = result.evidence.first { it.stage == "case" }
                assertEquals("observed account", evidence.input.getValue("username").jsonPrimitive.content)
                assertEquals(secret, evidence.input.getValue("password").jsonPrimitive.content)
                assertEquals(JsonPrimitive(true), evidence.output["binding"])
                val absent = runner.run("TRN-01", target, username = "", password = "")
                assertEquals("completed", absent.execution, absent.limitations.joinToString())
                assertEquals("absent", absent.evidence.first { it.stage == "case" }.input.getValue("condition").jsonPrimitive.content)
                assertFalse(absent.evidence.any { it.input.toString().contains("fallback secret") })
                assertTrue(grants.size >= 4)
                assertTrue(telemetry.snapshot().any { it.type == "assessment-result" })
            }
            server.join(2000)
            assertFalse(server.isAlive)
        }
    }

    @Test fun `TURN tests require a TURN listener and stop cancels before sending`() {
        ProtocolRunner(config, NetworkAuthorization(config) { true }, outcomes).use { runner ->
            assertEquals("error", runner.run("TRN-02", ProtocolTarget.parse("stun:127.0.0.1:3478")).execution)
            assertEquals("cancelled", runner.run("TRN-01", ProtocolTarget.parse("stun:127.0.0.1:3478"), { true }).execution)
        }
    }

    @Test fun `scenario runner needs a passing control and reports a demonstrated violation`() {
        val responses = ArrayDeque(listOf("""{"owner":"alice"}""", """{"owner":"alice"}"""))
        val sent = mutableListOf<Pair<String, Map<String, String>>>()
        val transport = object : ScenarioTransport {
            override fun http(method: String, url: String, headers: Map<String, String>, body: String): ScenarioTransport.HttpResult {
                sent += url to headers
                return ScenarioTransport.HttpResult(200, listOf("Content-Type" to "application/json"), responses.removeFirst())
            }
            override fun webSocket(url: String, headers: Map<String, String>) = error("unused")
        }
        val alice = webrtc.config.IdentityProfile("alice", headers = mapOf("Cookie" to "sid=alice"), origins = listOf("https://app.test"))
        val bob = webrtc.config.IdentityProfile("bob", headers = mapOf("Cookie" to "sid=bob"), origins = listOf("https://app.test"))
        val read = { identity: String -> ScenarioStep(identity, "https://app.test/api/statement", identity = identity,
            assertion = Assertion("/json/owner", JsonPrimitive("alice"))) }
        val scenario = Scenario("statement", "SIG-04", "Statement isolation", "Only alice reads alice's statement",
            control = listOf(read("alice")), cases = listOf(ScenarioCase("bob", listOf(read("bob")))), intervalMs = 100, timeoutSeconds = 10)
        val result = ScenarioRunner(transport, { true }, { false }).run(scenario, "run", "engagement", listOf(alice, bob))
        assertEquals("completed", result.execution, result.limitations.joinToString())
        assertEquals("policy-violation", result.security)
        assertEquals("passed", result.control)
        assertEquals("sid=bob", sent.last().second["Cookie"])
        result.validate()
        val blocked = ScenarioRunner(transport, { false }, { false }).run(scenario, "run2", "engagement", listOf(alice, bob))
        assertEquals("blocked", blocked.execution)
    }
}
