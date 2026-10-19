package webrtc.datachannel

import kotlinx.serialization.json.*
import kotlin.test.*

class DcCaseGeneratorTest {
    private val sender = Participant("agent-c", "https://bank.test/call", "customer", "customer", "main", "ep-cust")
    private val advisor = Participant("agent-a", "https://bank.test/call", "advisor", "advisor", "main", "ep-adv")
    private val isolation = Participant("agent-t", "https://bank.test/call", "isolation", "observer", "test", "ep-iso", "conf-test")
    private val jvb = DcTarget("datachannel", "dc1", label = "JVB data channel", pcId = "pc1", peerKind = "jvb", maxMessageSize = 262144)
    private val observedStats = """{"colibriClass":"EndpointStats","bitrate":{"upload":1},"connectionQuality":100,"serverRegion":"eu"}"""
    private fun ctx(others: List<Participant> = listOf(advisor, isolation), foreign: String = "ep-iso", target: DcTarget = jvb) = DcContext(sender, target, others, true,
        ColibriSchemas.select("", "2.3-105", emptySet()), outbound = mapOf("EndpointStats" to listOf(observedStats)), foreignEndpoint = foreign)
    private fun text(c: DcCase) = c.payload.parts.joinToString("") { it.text.orEmpty() }

    @Test fun `fuzz cases change one field or one structural property and always carry their marker`() {
        val cases = DcCaseGenerator(DcSuiteConfig(), 7).fuzzCases(ctx())
        assertTrue(cases.size > 100)
        assertEquals(cases.size, cases.map { it.marker }.distinct().size)
        cases.forEach { c -> assertTrue(text(c).contains(c.marker), "${c.title} lost its marker"); assertTrue(Markers.pattern.matches(c.marker)) }
        // The observed EndpointStats template is used rather than the schema example.
        val stats = cases.filter { it.messageClass == "EndpointStats" }
        assertTrue(stats.all { "Template: observed" in it.notes })
        val missing = stats.first { it.mutation == "missing@serverRegion" }
        val obj = Json.parseToJsonElement(text(missing)).jsonObject
        assertFalse("serverRegion" in obj); assertEquals(100, obj["connectionQuality"]!!.jsonPrimitive.int)
        // Server-to-client classes are not fuzzed as client messages (they are authorization cases).
        assertTrue(cases.none { it.messageClass in setOf("ServerHello", "DominantSpeakerEndpointChangeEvent") })
        assertTrue(cases.any { it.mutation == "malformed-trailing-comma" && it.expect == Expect.REJECT })
        assertTrue(cases.any { it.mutation.startsWith("unicode@") && text(it).contains("\\ud83d") })
        // msgPayload content is application data: tolerated by the bridge, judged at receivers.
        val payloadCases = cases.filter { it.messageClass == "EndpointMessage" && it.mutation.contains("@msgPayload.") }
        assertTrue(payloadCases.isNotEmpty() && payloadCases.all { it.expect == Expect.TOLERATE })
        // Non-forwarded control messages must never reach anyone.
        assertTrue(cases.filter { it.messageClass == "ReceiverVideoConstraints" }.all { it.expect == Expect.REJECT })
    }

    @Test fun `the same seed reproduces mutations and random payloads`() {
        fun shape(seed: Long) = DcCaseGenerator(DcSuiteConfig(), seed).let { g -> (g.fuzzCases(ctx()) + g.binaryCases(ctx())).map { it.mutation to it.payload.parts.map { p -> p.seed } } }
        assertEquals(shape(42), shape(42))
        assertNotEquals(shape(42).map { it.second }, shape(43).map { it.second })
    }

    @Test fun `size cases measure UTF-8 bytes and test maxMessageSize boundaries within caps`() {
        val cases = DcCaseGenerator(DcSuiteConfig(maxMessageBytes = 300000), 1).binaryCases(ctx())
        val boundary = cases.filter { it.mutation.startsWith("max-message-size") }
        assertEquals(listOf(262143L, 262144L, 262145L), boundary.map { it.payload.byteLength() })
        assertEquals(16385L, cases.single { it.mutation == "text-utf8-16385" }.payload.byteLength())
        assertTrue(cases.filter { it.payload.binary }.map { it.payload.kind }.containsAll(listOf("arraybuffer", "uint8array", "int16array", "float64array", "dataview", "blob")))
        assertEquals(Expect.REJECT, cases.single { it.mutation == "json-as-binary" }.expect)
        // A lower cap blocks the large boundaries instead of sending them.
        val capped = DcCaseGenerator(DcSuiteConfig(), 1).binaryCases(ctx())
        assertTrue(capped.filter { it.mutation.startsWith("max-message-size") }.all { it.preVerdict == Verdict.BLOCKED })
        // Colibri WebSocket has no SCTP limit.
        val ws = DcCaseGenerator(DcSuiteConfig(), 1).binaryCases(ctx(target = DcTarget("colibri-ws", socketId = "ws1")))
        assertEquals(Verdict.NOT_APPLICABLE, ws.single { it.mutation == "max-message-size" }.preVerdict)
    }

    @Test fun `authorization cases target intended, unauthorized and cross-room recipients`() {
        val cases = DcCaseGenerator(DcSuiteConfig(), 1).authzCases(ctx())
        val unicast = cases.single { it.mutation == "unicast-control" }
        assertEquals(setOf("agent-a"), unicast.intended); assertEquals(setOf("agent-t"), unicast.forbidden)
        val cross = cases.single { it.mutation == "cross-room-unicast" }
        assertEquals(Expect.REJECT, cross.expect); assertTrue(text(cross).contains("\"to\":\"ep-iso\""))
        assertEquals("ep-adv", cases.single { it.mutation == "spoof-from" }.spoofedFrom)
        assertTrue(cases.filter { it.direction == "server-to-client-from-client" }.map { it.messageClass }.containsAll(listOf("VideoSourcesMap", "DominantSpeakerEndpointChangeEvent")))
        assertTrue(cases.single { it.mutation == "foreign-source" }.let { text(it).contains("ep-adv-v0") })
        // Without a test-room endpoint the cross-room case is inconclusive rather than silently passing.
        val missing = DcCaseGenerator(DcSuiteConfig(), 1).authzCases(ctx(listOf(advisor), foreign = "")).single { it.mutation == "cross-room-unicast" }
        assertEquals(Verdict.INCONCLUSIVE, missing.preVerdict)
    }

    @Test fun `generic applications get inferred JSON mutations and no Colibri envelope cases`() {
        val generic = DcContext(sender, DcTarget("datachannel", "dc1", peerKind = "participant"), listOf(advisor), false, null,
            outbound = mapOf("" to listOf("""{"type":"chat","text":"hi","n":3}""")))
        val gen = DcCaseGenerator(DcSuiteConfig(), 1)
        val fuzz = gen.fuzzCases(generic)
        assertTrue(fuzz.all { it.expect == Expect.TOLERATE })
        assertTrue(fuzz.any { it.mutation == "negative@n" })
        assertTrue(gen.authzCases(generic).isEmpty())
        assertTrue(gen.probeText(generic, "wrtc000000000000").contains("\"type\":\"chat\""))
    }

    @Test fun `case budget is shared across families and never exceeded`() {
        val gen = DcCaseGenerator(DcSuiteConfig(), 1)
        val families = mapOf(DcScope.FUZZ to gen.fuzzCases(ctx()), DcScope.BINARY to gen.binaryCases(ctx()), DcScope.AUTHZ to gen.authzCases(ctx()), DcScope.REPLAY to emptyList())
        val (kept, dropped) = DcCaseGenerator.allocate(families, 40)
        assertEquals(40, kept.values.sumOf { it.size })
        assertTrue(kept.getValue(DcScope.AUTHZ).isNotEmpty() && kept.getValue(DcScope.BINARY).isNotEmpty())
        assertEquals(families.values.sumOf { it.size } - 40, dropped.values.sum())
        val (all, none) = DcCaseGenerator.allocate(mapOf(DcScope.AUTHZ to families.getValue(DcScope.AUTHZ)), 1000)
        assertEquals(families.getValue(DcScope.AUTHZ).size, all.getValue(DcScope.AUTHZ).size); assertEquals(0, none.values.sum())
    }

    @Test fun `schema generation follows configured version, ServerHello, then observed classes`() {
        assertEquals(1, ColibriSchemas.select("2.1-490", "2.3", emptySet()).generation)
        assertEquals(2, ColibriSchemas.select("", "2.2-12", emptySet()).generation)
        assertEquals(3, ColibriSchemas.select("", null, setOf("VideoSourcesMap")).generation)
        assertEquals(1, ColibriSchemas.select("", null, setOf("ForwardedEndpointsMessage")).generation)
        assertTrue(ColibriSchemas.select("", null, emptySet()).source.startsWith("assumed"))
        assertTrue(ColibriSchemas.forGeneration(1).any { it.name == "ReceiverVideoConstraints" && it.fields.any { f -> f.name == "selectedEndpoints" } })
        assertTrue(ColibriSchemas.forGeneration(3).none { it.name == "ForwardedEndpointsMessage" })
    }

    @Test fun `call control scripts parse, validate and generate frame-crossing selectors`() {
        val steps = CallControls.parse("# join\nnavigate https://bank.test/{room}\nwait iframe#v >>> button.join 5000\nfill input#name | Wrtc Tester\n@meet.example click button.leave\nwaitchannel\nsleep 200")
        assertEquals(listOf("navigate", "wait", "fill", "click", "waitchannel", "sleep"), steps.map { it.action })
        assertEquals(5000, steps[1].timeoutMs); assertEquals("iframe#v >>> button.join", steps[1].argument)
        assertEquals("Wrtc Tester", steps[2].text); assertEquals("meet.example", steps[3].frame)
        assertTrue(CallControls.script(steps[1])!!.contains("split('>>>')"))
        assertEquals("https://bank.test/r1", CallControls.substitute(steps[0].argument, mapOf("room" to "r1")))
        assertFailsWith<IllegalArgumentException> { CallControls.parse("teleport now") }
        assertFailsWith<IllegalArgumentException> { CallControls.parse("fill input#x") }
        assertFailsWith<IllegalArgumentException> { RunnerSession("bad/name").validate() }
    }
}
