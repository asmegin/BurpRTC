package webrtc.datachannel

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import webrtc.burp.IssueReporter
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import java.util.Base64
import kotlin.test.*

class DcPayloadsAndIssuesTest {
    private var markers = 0
    private fun marker() = "wrtc" + (++markers).toString().padStart(12, '0')

    @Test fun `custom payloads get markers, binary forms and cap checks`() {
        val (entries, problems) = CustomPayloads.parse(listOf(
            """{"type":"chat","text":"{marker}"}""", """{"type":"exact"}""", "hex:00 ff 7b", "base64:AAEC", "hex:zz", "A".repeat(200)), 100, ::marker)
        assertEquals(listOf(1, 2, 3, 4), entries.map { it.index })
        assertEquals("""{"type":"chat","text":"wrtc000000000001"}""", entries[0].spec.describe()); assertEquals("wrtc000000000001", entries[0].marker)
        assertEquals("", entries[1].marker)
        assertEquals(listOf(0, 255, 123), Base64.getDecoder().decode(entries[2].spec.parts.single().base64).map { it.toInt() and 255 })
        assertEquals("arraybuffer", entries[3].spec.kind); assertEquals(3L, entries[3].spec.byteLength())
        assertEquals(2, problems.size); assertTrue(problems[0].contains("Payload 5")); assertTrue(problems[1].contains("200 bytes"))
        val cases = DcCaseGenerator(DcSuiteConfig(), 1).customCases(entries)
        assertTrue(cases.all { it.scope == DcScope.FUZZ && it.expect == Expect.TOLERATE })
        assertEquals("custom-1", cases[0].mutation)
    }

    @Test fun `automatic is the default and custom sources need payloads`() {
        assertEquals("automatic", DcSuiteConfig().payloadSource)
        DcSuiteConfig().validate()
        assertFailsWith<IllegalArgumentException> { DcSuiteConfig(payloadSource = "custom").validate() }
        assertFailsWith<IllegalArgumentException> { DcSuiteConfig(payloadSource = "mine", customPayloads = listOf("x")).validate() }
        DcSuiteConfig(payloadSource = "both", customPayloads = listOf("x")).validate()
        DcSuiteConfig(payloadSource = "custom", customPayloadFile = "payloads.txt").validate()
    }

    private fun fail(caseId: String, scope: DcScope, mutation: String = "", expect: String = "reject", receipts: List<Receipt> = emptyList()) =
        DcCaseResult("run", caseId, scope.id, "t", Verdict.FAIL, listOf("why"), "datachannel", mutation = mutation, expect = expect, receipts = receipts,
            senderFrame = "https://bank.test/call", payload = "{}")

    @Test fun `each failure kind maps to a specific issue and only FAIL becomes an issue`() {
        assertEquals("spoof", DcIssues.classify(fail("authz-007", DcScope.AUTHZ, "spoof-from"))!!.category)
        assertEquals("direction", DcIssues.classify(fail("authz-009", DcScope.AUTHZ, "direction"))!!.category)
        assertEquals("isolation", DcIssues.classify(fail("authz-003", DcScope.AUTHZ, "cross-room-unicast"))!!.category)
        assertEquals("ws-admission", DcIssues.classify(fail("authz-ws-wrong-pwd", DcScope.AUTHZ))!!.category)
        assertEquals("termination", DcIssues.classify(fail("lifecycle-hangup", DcScope.REPLAY))!!.category)
        assertEquals("readmission", DcIssues.classify(fail("lifecycle-admission", DcScope.REPLAY))!!.category)
        assertEquals("client-error", DcIssues.classify(fail("fuzz-010", DcScope.FUZZ, "null@x", "tolerate", listOf(Receipt("a", "advisor", kind = "error"))))!!.category)
        assertEquals("relay", DcIssues.classify(fail("fuzz-011", DcScope.FUZZ, "unknown-class"))!!.category)
        assertEquals("load", DcIssues.classify(fail("load-rate-20", DcScope.LOAD))!!.category)
        assertNull(DcIssues.classify(fail("fuzz-012", DcScope.FUZZ).copy(verdict = Verdict.INCONCLUSIVE)))
    }

    @Test fun `runner failures become deduplicated Burp issues on the sender's site`() {
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ -> if (method.returnType.isInterface) proxy(method.returnType) else null }
        val telemetry = TelemetryTableModel()
        val issues = mutableListOf<IssueReporter.Spec>()
        IssueReporter({ issues += it }, ConfigStore(proxy(MontoyaApi::class.java) as MontoyaApi), telemetry).attach()
        val store = DcResultStore(telemetry)
        store.record(fail("authz-007", DcScope.AUTHZ, "spoof-from"))
        store.record(fail("authz-008", DcScope.AUTHZ, "spoof-from-foreign"))
        store.record(fail("fuzz-011", DcScope.FUZZ, "unknown-class").copy(verdict = Verdict.PASS))
        assertEquals(1, issues.size)
        assertEquals(AuditIssueSeverity.HIGH, issues.single().severity)
        assertTrue(issues.single().detail.contains("authz-007"))
        assertTrue(issues.single().baseUrl.startsWith("https://bank.test"))
    }
}
