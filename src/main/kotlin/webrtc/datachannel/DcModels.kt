package webrtc.datachannel

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.security.SecureRandom

/** Result classification. A successful send() or an absent response is never a PASS. */
enum class Verdict(val label: String) {
    PASS("PASS"), FAIL("FAIL"), INCONCLUSIVE("INCONCLUSIVE"), BLOCKED("BLOCKED"), NOT_APPLICABLE("NOT APPLICABLE")
}

/**
 * What a correct system does with a case. DELIVER: the intended recipient must receive it
 * (positive control). REJECT: no other participant may receive or process it. TOLERATE:
 * delivery is allowed, but no participant may error or lose session health.
 */
enum class Expect { DELIVER, REJECT, TOLERATE }

/** The RTCDataChannel scope items the coverage report maps every case to. */
enum class DcScope(val id: String, val title: String, val verification: String) {
    DISCOVERY("discovery", "Channel discovery and baseline",
        "Wait for open; capture normal traffic and connection health before testing. Unavailable channels are BLOCKED, not passed."),
    FUZZ("fuzz", "Application-message fuzzing",
        "Bridge responses, receiving-client behaviour, application errors and session health. Server-to-client classes are tested separately under authorization."),
    BINARY("binary", "Binary and size boundaries",
        "Browser rejection, queue acceptance, remote receipt and remote processing are distinguished; local rejection is never server-side validation."),
    AUTHZ("authz", "Message authorization and isolation",
        "Intended and unauthorized recipients are both observed, with a valid positive control. A missing observer or unsupported schema is INCONCLUSIVE."),
    REPLAY("replay", "Replay and lifecycle",
        "Stale messages must not affect a new session or an unauthorized recipient; closure is correlated with the initiating action."),
    LOAD("load", "Bounded load and channel churn",
        "Both clients, media quality, latency, errors and recovery are monitored; runs stop on configured degradation thresholds."),
    TRANSPORT("transport", "Colibri transport comparison",
        "The transport actually used is recorded; WebSocket results are kept separate from SCTP results."),
    NATIVE_SCTP("native-sctp", "Native SCTP / DCEP packet testing",
        "Requires a separate DTLS/SCTP-capable test peer with crash and log collection against controlled targets.");

    companion object {
        val runnable = entries.filter { it != NATIVE_SCTP }
        fun byId(id: String) = entries.firstOrNull { it.id == id }
    }
}

/** One payload segment. Text kinds concatenate strings; binary kinds concatenate bytes. */
@Serializable
data class PayloadPart(
    val text: String? = null,
    val repeat: String? = null,
    val count: Int = 0,
    val base64: String? = null,
    /** "zero" or "random" (seeded). */
    val fill: String? = null,
    val seed: Long = 0
) {
    fun bytes(): Long = when {
        text != null -> text.toByteArray(Charsets.UTF_8).size.toLong()
        repeat != null -> repeat.toByteArray(Charsets.UTF_8).size.toLong() * count
        base64 != null -> runCatching { java.util.Base64.getDecoder().decode(base64).size.toLong() }.getOrDefault(0)
        else -> count.toLong()
    }
}

@Serializable
data class PayloadSpec(val kind: String = "text", val parts: List<PayloadPart> = emptyList()) {
    /** UTF-8 bytes for text, raw bytes for binary kinds; matches the agent's measurement. */
    fun byteLength(): Long = parts.sumOf { it.bytes() }
    val binary: Boolean get() = kind != "text"
    /** Full text when the payload is small and literal (evidence); otherwise a bounded description. */
    fun describe(limit: Int = 4096): String = if (!binary && parts.all { it.text != null }) parts.joinToString("") { it.text!! }.let {
        if (it.length <= limit) it else it.take(limit) + "… (${it.length} chars)"
    } else "$kind: " + parts.joinToString(" + ") { p ->
        when {
            p.text != null -> "text(${p.text.take(64)}${if (p.text.length > 64) "…" else ""})"
            p.repeat != null -> "repeat('${p.repeat}' × ${p.count})"
            p.base64 != null -> "base64(${p.base64.take(32)})"
            p.fill == "random" -> "random(${p.count} bytes, seed ${p.seed})"
            else -> "${p.fill}(${p.count})"
        }
    }

    companion object {
        fun text(value: String) = PayloadSpec("text", listOf(PayloadPart(text = value)))
    }
}

/** A participating instrumented page and what is known about its identity. */
@Serializable
data class Participant(
    val agentId: String,
    val frame: String,
    val session: String = "",
    val role: String = "",
    val room: String = "main",
    val endpoint: String = "",
    val conference: String = ""
) {
    val label: String get() = listOf(session.ifBlank { "page ${agentId.takeLast(6)}" }, role, "room $room").filter { it.isNotBlank() }.joinToString(" · ")
}

/** The transport a case is sent through. */
@Serializable
data class DcTarget(
    val transport: String,
    val channelId: String = "",
    val socketId: String = "",
    val label: String = "",
    val pcId: String = "",
    val peerKind: String = "unknown",
    val maxMessageSize: Long? = null,
    val url: String = ""
) {
    val id: String get() = if (transport == "colibri-ws") socketId else channelId
    fun commandFields(): Map<String, String> = if (transport == "colibri-ws") mapOf("transport" to transport, "socketId" to socketId)
        else mapOf("transport" to transport, "channelId" to channelId)
}

/** A generated case. [marker] lets every instrumented recipient report what it observed. */
data class DcCase(
    val id: String,
    val scope: DcScope,
    val title: String,
    val payload: PayloadSpec,
    val marker: String,
    val expect: Expect,
    val messageClass: String = "",
    val mutation: String = "",
    val direction: String = "client-to-server",
    /** Agent IDs that must receive (DELIVER) or may receive (TOLERATE). Empty = everyone else. */
    val intended: Set<String> = emptySet(),
    /** Agent IDs that must not receive or process the message. Empty with REJECT = every other participant. */
    val forbidden: Set<String> = emptySet(),
    val spoofedFrom: String = "",
    val seed: Long = 0,
    val settleMs: Int? = null,
    val probe: Boolean = false,
    val target: DcTarget? = null,
    /** Set when the generator already knows the case cannot run (for example a size above the cap). */
    val preVerdict: Verdict? = null,
    val preReason: String = "",
    val notes: List<String> = emptyList()
)

@Serializable
data class Receipt(
    val agentId: String,
    val participant: String,
    val role: String = "",
    val room: String = "",
    val kind: String,
    val time: Long = 0,
    val colibriClass: String = "",
    val from: String = "",
    val to: String = "",
    val bytes: Long = 0,
    val latencyMs: Long? = null,
    val detail: String = ""
)

@Serializable
data class DcCaseResult(
    val runId: String,
    val caseId: String,
    val scope: String,
    val title: String,
    val verdict: Verdict,
    val reasons: List<String>,
    val transport: String = "",
    val direction: String = "",
    val messageClass: String = "",
    val mutation: String = "",
    val expect: String = "",
    val sender: String = "",
    val senderRole: String = "",
    val senderRoom: String = "",
    val senderEndpoint: String = "",
    val target: String = "",
    val payload: String = "",
    val payloadKind: String = "",
    val seed: Long = 0,
    val marker: String = "",
    val bytes: Long? = null,
    val queuedAt: Long = 0,
    val sentAt: Long? = null,
    val settledAt: Long? = null,
    val stage: String = "",
    val localError: String = "",
    val bufferedBefore: Long? = null,
    val bufferedAfter: Long? = null,
    val stateBefore: JsonElement? = null,
    val stateAfter: JsonElement? = null,
    val receipts: List<Receipt> = emptyList(),
    val errors: List<String> = emptyList(),
    val probe: String = "",
    val recovery: String = "",
    val bridgeLog: List<String> = emptyList(),
    val evidence: JsonObject? = null
)

@Serializable
data class CoverageRow(
    val scope: String,
    val title: String,
    val verification: String,
    val counts: Map<String, Int>,
    val caseIds: List<String>,
    val limitations: List<String>
)

@Serializable
data class DcRun(
    val runId: String,
    val startedAt: Long,
    val endedAt: Long,
    val seed: Long,
    val schema: String,
    val participants: List<Participant>,
    val sender: String,
    val transport: String,
    val results: List<DcCaseResult>,
    val coverage: List<CoverageRow>,
    val notes: List<String> = emptyList(),
    val stopReason: String = ""
)

/** Unique run markers. The agent scans for /wrtc[0-9a-z]{12}/. */
object Markers {
    private const val ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
    private val random = SecureRandom()
    val pattern = Regex("wrtc[0-9a-z]{12}")
    fun next(): String = "wrtc" + (1..12).map { ALPHABET[random.nextInt(ALPHABET.length)] }.joinToString("")
    /** 8-character stem; the agent appends a 4-character base-36 sequence for load messages. */
    fun stem(): String = "wrtc" + (1..8).map { ALPHABET[random.nextInt(ALPHABET.length)] }.joinToString("")
    fun loadMarker(stem: String, seq: Int): String = stem + seq.toString(36).padStart(4, '0')
}
