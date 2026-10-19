package webrtc.datachannel

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import kotlin.concurrent.thread
import kotlin.test.*

/**
 * Two simulated instrumented pages (customer sender, advisor observer) and a simulated bridge
 * that relays only well-formed EndpointMessages addressed to the advisor or broadcast.
 */
class DcSuiteRunnerTest {
    private val frame = "https://bank.test/call"
    private fun api(): MontoyaApi {
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ ->
            if (method.returnType.isInterface) proxy(method.returnType) else null
        }
        return proxy(MontoyaApi::class.java) as MontoyaApi
    }
    private val store = ConfigStore(api()).also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("bank.test"))) }
    private val telemetry = TelemetryTableModel()
    private val controller = ActiveTestController(store, { it.startsWith("https://bank.test") }, telemetry)
    @Volatile private var alive = true
    /** A loose bridge relays any EndpointMessage with a string recipient, even to unknown endpoints. */
    @Volatile private var loose = false

    private fun emit(obj: JsonObject) {
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), "", obj["type"]!!.jsonPrimitive.content, frame, "", false, "", obj.toString()))
        controller.observe(obj)
    }

    private fun heartbeat(agent: String, endpoint: String, hints: List<String>) = emit(buildJsonObject {
        put("type", "agent-state"); put("agent", agent); put("frame", frame); put("endpoint", endpoint)
        put("endpointHints", JsonArray(hints.map(::JsonPrimitive)))
        put("channels", buildJsonArray { add(buildJsonObject {
            put("channelId", "dc1"); put("pc", "pc1"); put("label", "JVB data channel"); put("state", "open"); put("peerKind", "jvb")
            put("protocol", ColibriSchemas.PROTOCOL); put("maxMessageSize", 262144); put("sctpState", "connected")
        }) })
        put("pcs", buildJsonArray { add(buildJsonObject { put("pcId", "pc1"); put("kind", "jvb"); put("connectionState", "connected") }) })
    })

    /** What the reference bridge does with a message from the customer. */
    private fun relayedTo(text: String): Boolean {
        val obj = runCatching { Json.parseToJsonElement(text) as? JsonObject }.getOrNull() ?: return false
        if ((obj["colibriClass"] as? JsonPrimitive)?.contentOrNull != "EndpointMessage") return false
        val to = obj["to"] as? JsonPrimitive ?: return false
        return to.isString && (loose || to.content in setOf("", "ep-adv"))
    }

    private fun agentLoop(agent: String) = thread(isDaemon = true) {
        while (alive) {
            heartbeat(agent, if (agent == "agent-c") "ep-cust" else "ep-adv", listOf(if (agent == "agent-c") "ep-adv" else "ep-cust"))
            for (command in controller.commands(agent, frame)) {
                val id = command["id"]!!.jsonPrimitive.content
                if (!controller.authorize(agent, frame, id)) continue
                val config = command["config"]!!.jsonObject
                when (command["type"]!!.jsonPrimitive.content) {
                    "dc-suite" -> config["cases"]!!.jsonArray.forEach { c ->
                        val case = c.jsonObject
                        val marker = case["marker"]!!.jsonPrimitive.content
                        val payload = case["payload"]!!.jsonObject
                        val text = payload["parts"]!!.jsonArray.joinToString("") { p -> p.jsonObject["text"]?.jsonPrimitive?.content ?: "" }
                        val binary = payload["kind"]?.jsonPrimitive?.content != "text"
                        emit(buildJsonObject {
                            put("type", "dc-case"); put("agent", agent); put("frame", frame); put("commandId", id); put("caseId", case["id"]!!.jsonPrimitive.content)
                            put("marker", marker); put("stage", "queued"); put("bytes", text.length); put("sentAt", System.currentTimeMillis()); put("settledAt", System.currentTimeMillis())
                            put("stateAfter", buildJsonObject { put("channel", "open") })
                        })
                        if (!binary && marker.isNotEmpty() && relayedTo(text)) emit(buildJsonObject {
                            put("type", "dc-markers"); put("agent", "agent-a"); put("frame", frame)
                            put("receipts", buildJsonArray { add(buildJsonObject {
                                put("marker", marker); put("kind", "dc"); put("t", System.currentTimeMillis()); put("from", "ep-cust"); put("colibriClass", "EndpointMessage")
                            }) })
                        })
                    }
                    "dc-health" -> emit(buildJsonObject {
                        put("type", "dc-health"); put("agent", agent); put("frame", frame); put("commandId", id); put("detail", "healthy")
                        put("peers", buildJsonArray { add(buildJsonObject { put("pcId", "pc1"); put("connectionState", "connected") }) })
                    })
                }
                emit(buildJsonObject { put("type", "command-result"); put("agent", agent); put("frame", frame); put("commandId", id); put("status", "completed") })
            }
            Thread.sleep(20)
        }
    }

    private fun runner(results: DcResultStore = DcResultStore(telemetry)) =
        DcSuiteRunner(store, controller, telemetry, results, sleeper = { Thread.sleep(minOf(it, 30)) })

    @AfterTest fun stopAgents() { alive = false }

    @Test fun `paired run classifies rejection, delivery and inference against a reference bridge`() {
        store.save(store.config.copy(dataChannelSuite = DcSuiteConfig(families = setOf("discovery", "fuzz", "binary", "authz"), maxCases = 60, receiptGraceMs = 50)))
        agentLoop("agent-c"); agentLoop("agent-a")
        Thread.sleep(200)
        val run = runner().run(DcSuiteRunner.Options(assignments = mapOf("agent-c" to ("customer" to "main"), "agent-a" to ("advisor" to "main"))))!!
        val byId = run.results.associateBy { it.caseId }
        assertEquals("", run.stopReason)
        assertEquals(Verdict.PASS, run.results.first { it.caseId.startsWith("control") }.verdict)
        assertEquals("customer", run.participants.first { it.agentId == "agent-c" }.role)
        // Malformed / unknown classes were not relayed: rejection is demonstrated by probes, not by silence alone.
        val structural = run.results.filter { it.scope == "fuzz" && it.expect == "reject" }
        assertTrue(structural.isNotEmpty() && structural.all { it.verdict == Verdict.PASS }, structural.filter { it.verdict != Verdict.PASS }.joinToString { "${it.caseId} ${it.verdict} ${it.reasons}" })
        // The unicast reached the advisor, but with no third observer its isolation is unverified.
        val unicast = run.results.single { it.mutation == "unicast-control" }
        assertEquals(Verdict.INCONCLUSIVE, unicast.verdict)
        assertTrue(unicast.reasons.first().startsWith("Delivered to"))
        assertEquals(Verdict.INCONCLUSIVE, run.results.single { it.mutation == "broadcast-isolation" }.verdict)
        assertEquals(Verdict.INCONCLUSIVE, run.results.single { it.mutation == "cross-room-unicast" }.verdict)
        // Binary to a Colibri bridge is not relayed.
        assertEquals(Verdict.PASS, run.results.single { it.mutation == "arraybuffer-16384-random" }.verdict)
        assertEquals(Verdict.NOT_APPLICABLE, byId.getValue("authz-ws-admission").verdict)
        assertTrue(run.results.none { it.verdict == Verdict.FAIL }, run.results.filter { it.verdict == Verdict.FAIL }.joinToString { "${it.caseId} ${it.reasons}" })
        assertEquals(DcScope.entries.size, run.coverage.size)
        assertTrue(run.coverage.first { it.scope == "authz" }.limitations.any { it.contains("test-room") })
        assertTrue(telemetry.snapshot().count { it.type == "dc-case-result" } == run.results.size)
        assertFalse(controller.observing)
    }

    @Test fun `a bridge that relays forbidden messages produces FAIL with recipient evidence`() {
        store.save(store.config.copy(dataChannelSuite = DcSuiteConfig(families = setOf("authz"), maxCases = 30, receiptGraceMs = 50)))
        agentLoop("agent-c"); agentLoop("agent-a")
        Thread.sleep(200)
        loose = true
        val run = runner().run(DcSuiteRunner.Options(assignments = mapOf("agent-c" to ("customer" to "main"), "agent-a" to ("advisor" to "main"))))!!
        val unknown = run.results.single { it.mutation == "unknown-endpoint" }
        assertEquals(Verdict.FAIL, unknown.verdict)
        assertEquals("agent-a", unknown.receipts.single().agentId)
    }

    @Test fun `custom payload source sends only your payloads as fuzz cases`() {
        store.save(store.config.copy(dataChannelSuite = DcSuiteConfig(families = setOf("fuzz"), payloadSource = "custom", receiptGraceMs = 50,
            customPayloads = listOf("""{"colibriClass":"EndpointMessage","to":"","msgPayload":{"m":"{marker}"}}""", """{"colibriClass":"Nope","m":"{marker}"}"""))))
        agentLoop("agent-c"); agentLoop("agent-a")
        Thread.sleep(200)
        val run = runner().run(DcSuiteRunner.Options(assignments = mapOf("agent-c" to ("customer" to "main"), "agent-a" to ("advisor" to "main"))))!!
        val fuzz = run.results.filter { it.scope == "fuzz" }
        assertEquals(listOf("custom-1", "custom-2"), fuzz.map { it.mutation })
        assertEquals(Verdict.PASS, fuzz[0].verdict); assertEquals("agent-a", fuzz[0].receipts.single().agentId)
        assertEquals(Verdict.PASS, fuzz[1].verdict); assertTrue(fuzz[1].receipts.isEmpty())
    }

    @Test fun `no open channel blocks every selected family`() {
        store.save(store.config.copy(dataChannelSuite = DcSuiteConfig(families = setOf("fuzz", "load"))))
        val run = runner().run()!!
        assertEquals(setOf("fuzz", "load"), run.results.map { it.scope }.toSet())
        assertTrue(run.results.all { it.verdict == Verdict.BLOCKED })
    }

}
