package webrtc.datachannel

import kotlinx.serialization.json.*
import kotlin.test.*

class DcClassifierTest {
    private val others = setOf("adv", "iso")
    private fun case(expect: Expect, intended: Set<String> = emptySet(), forbidden: Set<String> = emptySet(), spoofed: String = "", scope: DcScope = DcScope.FUZZ) =
        DcCase("c-1", scope, "case", PayloadSpec.text("x"), "wrtc000000000001", expect, intended = intended, forbidden = forbidden, spoofedFrom = spoofed)
    private fun sent(stage: String = "queued", error: String = "", channel: String = "open") = buildJsonObject {
        put("stage", stage); put("error", error); put("sentAt", 1000); put("settledAt", 1600); put("stateAfter", buildJsonObject { put("channel", channel) })
    }
    private fun receipt(agent: String, kind: String = "dc", from: String = "") = Receipt(agent, agent, kind = kind, time = 1100, from = from, detail = "boom")
    private fun classify(c: DcCase, s: JsonObject? = sent(), receipts: List<Receipt> = emptyList(), probe: Boolean? = true, control: Boolean = true, live: Set<String> = others) =
        DcClassifier.classify(CaseObservation(c, s, receipts, emptyList(), probe, control, live, others))

    @Test fun `successful send and silence alone never pass`() {
        assertEquals(Verdict.INCONCLUSIVE, classify(case(Expect.REJECT), probe = null).first)
        assertEquals(Verdict.INCONCLUSIVE, classify(case(Expect.TOLERATE), control = false).first)
        assertEquals(Verdict.INCONCLUSIVE, classify(case(Expect.REJECT), live = emptySet()).first)
        assertEquals(Verdict.PASS, classify(case(Expect.REJECT)).first)
    }

    @Test fun `browser rejection is never server-side validation and unexecuted cases are blocked`() {
        val (verdict, reasons) = classify(case(Expect.REJECT), sent("browser-rejected", "TypeError: too large"))
        assertEquals(Verdict.INCONCLUSIVE, verdict)
        assertTrue(reasons.single().contains("server-side validation was not exercised"))
        assertEquals(Verdict.BLOCKED, classify(case(Expect.REJECT), null).first)
        assertEquals(Verdict.BLOCKED, classify(case(Expect.REJECT), sent("blocked", "Target is not open")).first)
    }

    @Test fun `delivery to an unauthorized recipient fails and intended delivery needs a live unauthorized observer`() {
        assertEquals(Verdict.FAIL, classify(case(Expect.REJECT), receipts = listOf(receipt("iso"))).first)
        val isolation = case(Expect.DELIVER, setOf("adv"), setOf("iso"), scope = DcScope.AUTHZ)
        assertEquals(Verdict.FAIL, classify(isolation, receipts = listOf(receipt("adv"), receipt("iso", "dom"))).first)
        assertEquals(Verdict.PASS, classify(isolation, receipts = listOf(receipt("adv"))).first)
        assertEquals(Verdict.INCONCLUSIVE, classify(isolation, receipts = listOf(receipt("adv")), live = setOf("adv")).first)
        assertEquals(Verdict.FAIL, classify(case(Expect.DELIVER, setOf("adv"))).first, "a failed positive control is a FAIL")
    }

    @Test fun `spoofed identities, marker errors and session health`() {
        val spoof = case(Expect.TOLERATE, spoofed = "ep-adv")
        assertEquals(Verdict.FAIL, classify(spoof, receipts = listOf(receipt("adv", from = "ep-adv"))).first)
        assertEquals(Verdict.PASS, classify(spoof, receipts = listOf(receipt("adv", from = "ep-cust"))).first)
        assertEquals(Verdict.FAIL, classify(case(Expect.TOLERATE), receipts = listOf(receipt("adv", "error"))).first)
        assertEquals(Verdict.INCONCLUSIVE, classify(case(Expect.TOLERATE), probe = false).first)
        val closed = classify(case(Expect.REJECT), sent(channel = "closed"))
        assertEquals(Verdict.PASS, closed.first); assertTrue(closed.second.any { it.contains("closed") })
        assertEquals(Verdict.NOT_APPLICABLE, DcClassifier.classify(CaseObservation(case(Expect.REJECT).copy(preVerdict = Verdict.NOT_APPLICABLE, preReason = "n/a"),
            null, emptyList(), emptyList(), null, true, others, others)).first)
    }

    @Test fun `WebSocket admission and load thresholds`() {
        fun admission(opened: Boolean, outcome: String) = buildJsonObject { put("opened", opened); put("outcome", outcome); put("firstClass", "ServerHello"); put("closeCode", 1008) }
        assertEquals(Verdict.FAIL, DcClassifier.admission(admission(true, "message"), true).first)
        assertEquals(Verdict.PASS, DcClassifier.admission(admission(false, "closed"), true).first)
        assertEquals(Verdict.INCONCLUSIVE, DcClassifier.admission(admission(false, "closed"), false).first)
        assertEquals(Verdict.INCONCLUSIVE, DcClassifier.admission(admission(false, "connect-timeout"), true).first)
        val cfg = DcSuiteConfig()
        assertEquals(Verdict.PASS, DcClassifier.load(DcClassifier.LoadMetrics(50, 1.0, 120, 0.5, false), cfg, true).first)
        assertEquals(Verdict.FAIL, DcClassifier.load(DcClassifier.LoadMetrics(50, 0.5, 120, 0.0, false), cfg, true).first)
        assertEquals(Verdict.FAIL, DcClassifier.load(DcClassifier.LoadMetrics(50, 1.0, 9000, 0.0, false), cfg, true).first)
        assertEquals(Verdict.INCONCLUSIVE, DcClassifier.load(DcClassifier.LoadMetrics(50, null, null, null, false), cfg, false).first)
        assertEquals(95L, DcClassifier.percentile((1L..100L).toList(), 0.95))
    }

    @Test fun `coverage maps every scope item including native SCTP as a separate limitation`() {
        val rows = DcCoverage.compute(listOf(DcCaseResult("r", "fuzz-001", "fuzz", "t", Verdict.PASS, listOf("ok"))), mapOf(DcScope.AUTHZ to listOf("No test room")))
        assertEquals(DcScope.entries.size, rows.size)
        assertEquals(mapOf("PASS" to 1), rows.first { it.scope == "fuzz" }.counts)
        assertTrue(rows.first { it.scope == "authz" }.limitations.first() == "No test room")
        assertTrue(rows.first { it.scope == "native-sctp" }.limitations.any { it.contains("DTLS/SCTP") })
        assertTrue(DcCoverage.text(rows).contains("Application-message fuzzing: PASS 1"))
    }
}
