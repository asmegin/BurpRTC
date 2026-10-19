package webrtc.datachannel

import kotlinx.serialization.Serializable

/**
 * DataChannel runner settings, persisted in the Burp project. Every limit is a hard cap
 * enforced again by the agent; defaults are deliberately conservative.
 */
@Serializable
data class DcSuiteConfig(
    val families: Set<String> = DcScope.runnable.map { it.id }.toSet(),
    val maxCases: Int = 200,
    val maxMessageBytes: Int = 65536,
    val maxTotalBytes: Int = 8 * 1048576,
    val maxDurationSeconds: Int = 900,
    val settleMs: Int = 600,
    val receiptGraceMs: Int = 1500,
    /** A delivery probe follows every N cases; a failed probe triggers recovery and isolation. */
    val probeEvery: Int = 5,
    val maxBufferedAmount: Int = 1048576,
    val maxNesting: Int = 64,
    val maxChannels: Int = 8,
    val churnIterations: Int = 5,
    val loadRates: List<Int> = listOf(5, 10, 20),
    val loadStepSeconds: Int = 5,
    val burstSize: Int = 25,
    val minDeliveryRatio: Double = 0.9,
    val maxP95LatencyMs: Int = 2000,
    val maxPacketLossIncreasePct: Double = 5.0,
    /** 0 = a new random seed per run (always recorded with the results). */
    val seed: Long = 0,
    /** Blank = detect from ServerHello / observed message classes. Example: 2.3-105-ge155b81e. */
    val jitsiVersion: String = "",
    /** Blank = automatic. Otherwise a message containing {marker}, for example {"type":"chat","text":"{marker}"}. */
    val probeTemplate: String = "",
    /** Optional endpoint ID of a participant in the separate test room, when it cannot be detected. */
    val testRoomEndpoint: String = "",
    val protectedMessages: List<ProtectedMessage> = emptyList(),
    /** Message-fuzzing payloads: "automatic" (generated), "custom" (yours only) or "both" (yours first). */
    val payloadSource: String = "automatic",
    /** Your payloads, one per entry. See [CustomPayloads] for {marker}, hex: and base64: forms. */
    val customPayloads: List<String> = emptyList(),
    /** Optional file with one payload per line, read when the run starts. */
    val customPayloadFile: String = "",
    val expectDisconnectOnHangup: Boolean = true,
    /** "denied", "allowed" or "unknown": what a customer re-join after the advisor ends the call should do. */
    val rejoinAfterHangup: String = "denied",
    val rejoinAfterRemoval: String = "denied",
    /** Optional local copy / mount of the bridge log (for example jvb.log); new lines are attached to results. */
    val bridgeLogPath: String = ""
) {
    fun includes(scope: DcScope) = scope.id in families

    fun validate() {
        require(families.all { DcScope.byId(it) != null }) { "Unknown test family" }
        require(maxCases in 1..1000) { "Use 1-1000 cases per run" }
        require(maxMessageBytes in 1..1048576) { "Limit each message to 1 MiB" }
        require(maxTotalBytes in 1..64 * 1048576) { "Limit each run to 64 MiB" }
        require(maxDurationSeconds in 30..7200) { "Use a 30-7200 second run budget" }
        require(settleMs in 50..10000 && receiptGraceMs in 0..15000) { "Use a 50-10000 ms settle window and 0-15000 ms receipt grace" }
        require(probeEvery in 1..50) { "Probe every 1-50 cases" }
        require(maxBufferedAmount in 1024..16 * 1048576) { "Use a 1 KiB-16 MiB send buffer cap" }
        require(maxNesting in 2..512) { "Use a nesting bound of 2-512" }
        require(maxChannels in 1..64 && churnIterations in 1..64) { "Use 1-64 churn channels" }
        require(loadRates.size in 0..8 && loadRates.all { it in 1..200 }) { "Use up to 8 load steps of 1-200 messages/second" }
        require(loadStepSeconds in 1..60 && burstSize in 0..1000) { "Use 1-60 second load steps and bursts of up to 1000" }
        require(minDeliveryRatio in 0.0..1.0 && maxP95LatencyMs in 50..60000 && maxPacketLossIncreasePct in 0.0..100.0) { "Invalid degradation thresholds" }
        require(probeTemplate.isBlank() || probeTemplate.contains("{marker}")) { "The probe template must contain {marker}" }
        require(rejoinAfterHangup in EXPECTATIONS && rejoinAfterRemoval in EXPECTATIONS) { "Re-join expectations are denied, allowed or unknown" }
        require(payloadSource in PAYLOAD_SOURCES) { "Payload source is automatic, custom or both" }
        require(payloadSource == "automatic" || customPayloads.isNotEmpty() || customPayloadFile.isNotBlank()) {
            "Add your payloads or choose a payload file, or use automatic payloads"
        }
        require(customPayloads.size <= CustomPayloads.MAX) { "Use up to ${CustomPayloads.MAX} custom payloads" }
        require(protectedMessages.size <= 20) { "Use up to 20 protected messages" }
        protectedMessages.forEach(ProtectedMessage::validate)
    }

    companion object {
        val EXPECTATIONS = setOf("denied", "allowed", "unknown")
        val PAYLOAD_SOURCES = setOf("automatic", "custom", "both")
    }
}

/**
 * Tester-supplied fuzz payloads. Each entry is sent once as its own case:
 *  - text containing {marker} gets a fresh case marker, so recipients can report it;
 *  - text without {marker} is sent byte-for-byte and matched at recipients by hash;
 *  - "hex:0a ff 00" and "base64:AAEC" send binary (ArrayBuffer) payloads.
 * In a file, lines starting with # are comments and blank lines are skipped.
 */
object CustomPayloads {
    const val MAX = 500

    data class Entry(val index: Int, val raw: String, val spec: PayloadSpec, val marker: String)

    fun fromFile(path: String): List<String> {
        val file = java.io.File(path)
        require(file.isFile) { "Payload file not found: $path" }
        require(file.length() <= 16L * 1048576) { "Payload file exceeds 16 MiB" }
        return file.readLines(Charsets.UTF_8).filter { it.isNotBlank() && !it.startsWith("#") }
    }

    /** Parse entries; [marker] supplies a fresh marker for each {marker} entry. */
    fun parse(entries: List<String>, maxBytes: Int, marker: () -> String): Pair<List<Entry>, List<String>> {
        val problems = mutableListOf<String>()
        val out = entries.take(MAX).mapIndexedNotNull { i, raw ->
            val spec = runCatching {
                when {
                    raw.startsWith("hex:", true) -> {
                        val hex = raw.substring(4).replace(Regex("\\s"), "")
                        require(hex.length % 2 == 0 && hex.matches(Regex("[0-9a-fA-F]*"))) { "invalid hex" }
                        PayloadSpec("arraybuffer", listOf(PayloadPart(base64 = java.util.Base64.getEncoder().encodeToString(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()))))
                    }
                    raw.startsWith("base64:", true) -> {
                        val value = raw.substring(7).trim()
                        java.util.Base64.getDecoder().decode(value)
                        PayloadSpec("arraybuffer", listOf(PayloadPart(base64 = value)))
                    }
                    else -> PayloadSpec.text(raw)
                }
            }.getOrElse { problems += "Payload ${i + 1}: ${it.message}"; return@mapIndexedNotNull null }
            val m = if (!spec.binary && raw.contains("{marker}")) marker() else ""
            val final = if (m.isNotEmpty()) PayloadSpec.text(raw.replace("{marker}", m)) else spec
            if (final.byteLength() > maxBytes) { problems += "Payload ${i + 1}: ${final.byteLength()} bytes exceeds the $maxBytes-byte cap"; return@mapIndexedNotNull null }
            Entry(i + 1, raw, final, m)
        }
        if (entries.size > MAX) problems += "Only the first $MAX payloads are used"
        return out to problems
    }
}

/**
 * An application message only some roles may send, for example an advisor-only "mute" or
 * "end meeting" command. The runner sends it from an allowed role first (positive control:
 * the recipient's protected state must change), restores state, then sends it from a role
 * that is not allowed and checks the protected state did not change.
 */
@Serializable
data class ProtectedMessage(
    val name: String,
    /** Message text containing {marker}; {to} is replaced with the recipient endpoint ID. */
    val template: String,
    val allowedRoles: Set<String> = setOf("advisor"),
    /** Role whose session receives the message and whose state is probed. */
    val recipientRole: String = "customer",
    /** JavaScript expression evaluated in the recipient session, for example document.querySelector('.muted') !== null */
    val stateProbe: String = "",
    /** Call-control steps run on the recipient session to restore state after the positive control. */
    val restore: String = ""
) {
    fun validate() {
        require(name.isNotBlank() && template.contains("{marker}")) { "Protected messages need a name and a template containing {marker}" }
        require(template.length <= 65536 && stateProbe.length <= 8192 && restore.length <= 8192) { "Protected message is too long" }
    }
}

/** One controlled browser session the integrated runner launches and drives. */
@Serializable
data class RunnerSession(
    val name: String,
    /** customer, advisor, observer (any business role from Setup). */
    val role: String = "customer",
    /** "main" for the call under test, "test" for the separate isolation room. */
    val room: String = "main",
    val url: String = "",
    /** Optional Setup identity whose headers / cookies the session uses. */
    val identity: String = "",
    val join: String = "",
    val leave: String = "",
    val hangup: String = "",
    val remove: String = "",
    /** JavaScript returning this session's endpoint ID when the agent cannot detect it. */
    val endpointExpr: String = ""
) {
    fun validate() {
        require(name.matches(Regex("[A-Za-z0-9 _.-]{1,40}"))) { "Session names use 1-40 letters, digits, spaces, dots, dashes or underscores" }
        require(room in setOf("main", "test")) { "Room is main or test" }
        require(url.isBlank() || url.startsWith("https://") || url.startsWith("http://")) { "Start URLs must be http(s)" }
        listOf(join, leave, hangup, remove).forEach { CallControls.parse(it) }
    }
}

@Serializable
data class BrowserRunnerConfig(
    /** Blank = Burp's bundled Chromium, then Chrome / Edge / Chromium. */
    val browserPath: String = "",
    /** Blank = the first Burp proxy listener, else 127.0.0.1:8080. */
    val proxy: String = "",
    val headless: Boolean = false,
    /** Keep each session's browser profile so logins survive between runs. */
    val keepProfiles: Boolean = true,
    val mainRoom: String = "",
    val testRoom: String = "",
    val joinTimeoutSeconds: Int = 45,
    val sessions: List<RunnerSession> = emptyList()
) {
    fun validate() {
        require(sessions.size <= 6) { "Use up to 6 runner sessions" }
        require(sessions.map { it.name }.distinct().size == sessions.size) { "Session names must be unique" }
        require(joinTimeoutSeconds in 5..300) { "Use a 5-300 second join timeout" }
        require(proxy.isBlank() || proxy.matches(Regex("[A-Za-z0-9.\\[\\]:-]+:[0-9]{1,5}"))) { "Proxy is host:port, for example 127.0.0.1:8080" }
        sessions.forEach(RunnerSession::validate)
    }
}
