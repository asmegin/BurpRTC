package webrtc.workflow

import burp.api.montoya.MontoyaApi
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.config.IdentityProfile
import webrtc.internals.InternalsComparator
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RunAllControllerTest {
    @Test fun `run all emits every checklist item and shares authorization evidence`() {
        val store = freshStore()
        val telemetry = TelemetryTableModel()
        val controller = ActiveTestController(store, { true }, telemetry)
        val lines = mutableListOf<RunAllController.Line>()
        RunAllController(store, controller, telemetry, authzResults = {
            listOf(webrtc.authz.AuthzResult("https://example.test/api", "unauth", 200, 10, "hash", true, true, "test", null))
        }).run { lines += it }
        webrtc.report.CoverageCheck.entries.forEach { check ->
            assertTrue(lines.any { it.text.startsWith("${check.title} — ") }, check.title)
        }
        assertTrue(lines.any { it.text.startsWith("Signaling authentication tests — ") && it.level == RunAllController.Level.WARN && it.text.contains("Review required") })
        assertTrue(lines.any { it.text.startsWith("RTP packet fuzzing — ") && it.level == RunAllController.Level.SKIP })
    }
    @Test fun `TLS report includes positive findings and incomplete checks without claiming secure`() {
        val store = freshStore()
        val telemetry = TelemetryTableModel()
        telemetry.add(rawEvent("tls-scan-result", """{"target":"turns:example.test:5349","result":{"status":"partial","checks":[{"name":"robot","status":"error","summary":"ROBOT timed out"}],"findings":[{"level":"finding","text":"TLS 1.0 accepted"}]}}"""))
        telemetry.add(rawEvent("tls-scan-error", """{"target":"https://example.test","result":{"status":"cancelled","error":"stopped"}}"""))
        val lines = mutableListOf<RunAllController.Line>()
        RunAllController(store, ActiveTestController(store, { true }, telemetry), telemetry).passiveReport { lines.add(it) }
        assertTrue(lines.any { it.level == RunAllController.Level.FINDING && it.text.contains("TLS 1.0 accepted") })
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("ROBOT timed out") })
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("cancelled") })
        assertTrue(lines.any { it.text.contains("media DTLS or SRTP") })
        assertFalse(lines.any { it.level == RunAllController.Level.OK && it.text.contains("TLS") })
    }
    @Test fun `passive report explains unopened channels and peer failures without inventing a vulnerability`() {
        val store = freshStore()
        val telemetry = TelemetryTableModel()
        telemetry.add(rawEvent("dc-state", """{"agent":"a","channelId":"dc1","state":"closed","everOpened":false,"elapsedMs":159,"connectionState":"failed","iceConnectionState":"failed","signalingState":"stable","sctpState":"closed"}""").copy(pcId = "pc1"))
        telemetry.add(rawEvent("pc-state", """{"agent":"a","connectionState":"failed","iceConnectionState":"failed","signalingState":"closed","sctpState":"closed","action":"close-called"}""").copy(pcId = "pc1"))
        val lines = mutableListOf<RunAllController.Line>()
        RunAllController(store, ActiveTestController(store, { true }, telemetry), telemetry).passiveReport { lines.add(it) }
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("closed before reaching open after 159ms") })
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("ICE or connection failure") })
        assertTrue(lines.any { it.text.contains("page called RTCPeerConnection.close()") })
        assertFalse(lines.any { it.level == RunAllController.Level.FINDING })
    }
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

    private fun freshStore(): ConfigStore { persisted = null; return ConfigStore(api()) }

    private fun runReport(store: ConfigStore, telemetry: TelemetryTableModel): List<RunAllController.Line> {
        val controller = ActiveTestController(store, { true }, telemetry) { System.currentTimeMillis() }
        val lines = mutableListOf<RunAllController.Line>()
        RunAllController(store, controller, telemetry).run { lines.add(it) }
        return lines
    }

    private fun event(type: String, private: Boolean = false) =
        TelemetryEvent(1, "00:00:00.000", type, "https://example.test/call", "", private, "$type summary", "{}")

    private fun rawEvent(type: String, raw: String) =
        TelemetryEvent(1, "00:00:00.000", type, "https://example.test/call", "", false, "$type summary", raw)

    private fun iceEvent(candidate: String, private: Boolean = false) =
        rawEvent("ice", """{"type":"ice","candidate":"$candidate"}""").copy(private = private)

    @Test fun `unconfigured run warns and skips live checks without throwing`() {
        val store = freshStore() // injection off, empty allow-list by default
        val lines = runReport(store, TelemetryTableModel())
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("injection is OFF", ignoreCase = true) })
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("allow-list is empty", ignoreCase = true) })
        assertTrue(lines.any { it.level == RunAllController.Level.SKIP && it.text.contains("Configuration is not ready") })
        // Empty telemetry is reported as a skip, and the run always reaches the summary.
        assertTrue(lines.any { it.level == RunAllController.Level.SKIP && it.text.contains("No telemetry collected yet") })
        assertTrue(lines.any { it.text.contains("Run all complete") })
    }

    @Test fun `private ICE candidate is surfaced as a privacy warning`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(iceEvent("candidate:1 1 UDP 1 192.168.1.5 54400 typ host", private = true))
        val lines = runReport(store, telemetry)
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("client host address 192.168.1.5") })
        assertTrue(lines.any { it.level == RunAllController.Level.OK && it.text.contains("Agent installed") })
        // Configured but with no live agent, live checks are skipped (not run).
        assertTrue(lines.any { it.level == RunAllController.Level.SKIP && it.text.contains("No live in-scope browser page") })
    }

    @Test fun `crypto SDES and TURN relay findings are surfaced`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(rawEvent("crypto", """{"type":"crypto","detail":"dtls=? srtp=? tls=?"}"""))
        telemetry.add(rawEvent("sdp-remote", """{"type":"sdp-remote","sdp":"v=0\r\nm=audio 9 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:x\r\na=rtpmap:0 PCMU/8000\r\n"}"""))
        telemetry.add(rawEvent("ice-probe-result", """{"type":"ice-probe-result","counts":{"host":1,"srflx":1,"relay":2}}"""))
        val lines = runReport(store, telemetry)

        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("encryption status is unknown") })
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("SDES key exchange") })
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("TURN relay allocation") })
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("Codecs advertised") && it.text.contains("PCMU") })
    }

    @Test fun `imported webrtc-internals comparison is surfaced`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(rawEvent("internals-comparison",
            InternalsComparator.encodeLines(listOf(
                InternalsComparator.Line(InternalsComparator.Level.FINDING, "weak cipher in Chrome dump")
            ))))
        val lines = runReport(store, telemetry)
        assertTrue(lines.any {
            it.level == RunAllController.Level.FINDING &&
                it.text.contains("Chrome webrtc-internals") && it.text.contains("weak cipher")
        })
    }

    @Test fun `guessable configured identifiers are warned`() {
        val store = freshStore().also {
            it.save(it.config.copy(
                identifierKeys = listOf("roomId"),
                identities = listOf(
                    IdentityProfile("alice", identifiers = mapOf("roomId" to "1001")),
                    IdentityProfile("bob", identifiers = mapOf("roomId" to "1002"))
                )
            ))
        }
        val lines = runReport(store, TelemetryTableModel())
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("roomId") && it.text.contains("guessable", ignoreCase = true) })
    }

    @Test fun `passive report covers config and telemetry without live checks`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(iceEvent("candidate:1 1 UDP 1 192.168.1.5 54400 typ host", private = true))
        val lines = mutableListOf<RunAllController.Line>()
        val controller = ActiveTestController(store, { true }, telemetry) { System.currentTimeMillis() }
        RunAllController(store, controller, telemetry).passiveReport { lines.add(it) }

        assertTrue(lines.any { it.level == RunAllController.Level.OK && it.text.contains("Configuration looks ready") })
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("client host address 192.168.1.5") })
        // Passive: it must not mention running or queuing live active checks.
        assertFalse(lines.any { it.text.contains("Live active checks") || it.text.contains("queued") })
    }

    @Test fun `authz guidance depends on identity count`() {
        val one = freshStore().also { it.save(it.config.copy(identities = listOf(IdentityProfile("alice")))) }
        assertTrue(runReport(one, TelemetryTableModel()).any {
            it.level == RunAllController.Level.SKIP && it.text.contains("at least two identities")
        })

        val two = freshStore().also {
            it.save(it.config.copy(identities = listOf(IdentityProfile("alice"), IdentityProfile("bob"))))
        }
        val lines = runReport(two, TelemetryTableModel())
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("2 identities configured") })
        assertFalse(lines.any { it.text.contains("at least two identities") })
    }

    @Test fun `public ICE address and missing relay policy are flagged`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(iceEvent("candidate:2 1 UDP 1 203.0.113.9 54400 typ srflx raddr 10.0.0.7 rport 54400"))
        val lines = runReport(store, telemetry)
        assertFalse(lines.any { it.level == RunAllController.Level.FINDING })
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("client srflx address") })
    }

    @Test fun `relay policy suppresses the exposure warning`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(rawEvent("pc-new", """{"type":"pc-new","detail":"{\"iceServers\":[],\"iceTransportPolicy\":\"relay\"}"}"""))
        telemetry.add(iceEvent("candidate:2 1 UDP 1 203.0.113.9 54400 typ srflx raddr 10.0.0.7 rport 54400"))
        val lines = runReport(store, telemetry)
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("policy mismatch") })
        assertFalse(lines.any { it.text.contains("No relay-only") })
    }

    @Test fun `deeper getStats snapshot reports payload types roles and loss`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(rawEvent("stats-snapshot", """
            {"type":"stats-snapshot","pc":"pc1","transport":{"dtlsRole":"client","iceRole":"controlling"},
             "pair":"203.0.113.9 <-> 198.51.100.4","rtp":[{"direction":"inbound","kind":"audio","payloadType":111,"packets":950,"packetsLost":50,"jitter":0.004,"codec":"audio/opus"}],
             "candidates":[],"certificates":[],"truncated":false}
        """.trimIndent()))
        val lines = runReport(store, telemetry)
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("payload type") && it.text.contains("111") })
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("DTLS role client") })
        assertTrue(lines.any { (it.level == RunAllController.Level.WARN || it.level == RunAllController.Level.INFO) && it.text.contains("Inbound RTP loss") })
    }

    @Test fun `weak SDP fingerprint hash and ICE credential hygiene are surfaced`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(rawEvent("sdp-remote", """{"type":"sdp-remote","sdp":"v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-1 AA:BB\r\na=rtpmap:111 opus/48000/2\r\na=ice-ufrag:xy\r\na=ice-pwd:short\r\n"}"""))
        val lines = runReport(store, telemetry)
        assertTrue(lines.any { it.level == RunAllController.Level.FINDING && it.text.contains("Weak DTLS fingerprint hash") })
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("ICE credential hygiene") })
    }

    @Test fun `signaling endpoint metadata is reported passively`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        val lines = mutableListOf<RunAllController.Line>()
        val controller = ActiveTestController(store, { true }, telemetry) { System.currentTimeMillis() }
        RunAllController(store, controller, telemetry, signalingEndpoints = {
            listOf(SignalingMetadata.Endpoint("https://example.test:8443", true, false, 3))
        }).passiveReport { lines.add(it) }
        assertTrue(lines.any { it.level == RunAllController.Level.INFO && it.text.contains("https://example.test:8443") })
        assertTrue(lines.any { it.level == RunAllController.Level.WARN && it.text.contains("Strict-Transport-Security") })
    }

    @Test fun `unparseable DTLS certificate is reported without aborting the run`() {
        val store = freshStore().also { it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test"))) }
        val telemetry = TelemetryTableModel()
        telemetry.add(event("installed"))
        telemetry.add(rawEvent("dtls-cert", """{"type":"dtls-cert","pc":"pc1","role":"remote","algorithm":"sha-256","fingerprint":"AA","base64":"###"}"""))
        val lines = runReport(store, telemetry)
        assertTrue(lines.any { it.text.contains("could not be analysed") })
    }
}
