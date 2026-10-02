package webrtc.telemetry

import kotlinx.serialization.json.*
import webrtc.config.Detectors
import webrtc.config.SdpDocument

/** Shared interpretations for Run All and every report renderer. */
object EvidenceAnalysis {
    fun objectOf(event: TelemetryEvent): JsonObject = runCatching { Json.parseToJsonElement(event.raw) as? JsonObject }.getOrNull() ?: JsonObject(emptyMap())
    fun field(event: TelemetryEvent, name: String): String = (objectOf(event)[name] as? JsonPrimitive)?.contentOrNull.orEmpty()
    fun peer(event: TelemetryEvent) = listOf(event.frame, field(event, "agent"), event.pcId)
    data class Privacy(val event: TelemetryEvent, val text: String, val policyMismatch: Boolean)
    fun privacy(events: List<TelemetryEvent>): List<Privacy> = events.filter { it.type == "ice" }.mapNotNull { event ->
        val candidate = Detectors.parseCandidate(field(event, "candidate")) ?: return@mapNotNull null
        val config = events.filter { peer(it) == peer(event) && it.seq <= event.seq && it.type in setOf("pc-new", "pc-config") }.maxByOrNull { it.seq }
        val policy = config?.let {
            field(it, "iceTransportPolicy").ifBlank {
                runCatching { Json.parseToJsonElement(field(it, "detail")).jsonObject["iceTransportPolicy"]?.jsonPrimitive?.content }.getOrNull().orEmpty()
            }
        }.orEmpty().ifBlank { "unknown" }
        val relay = candidate.type == "relay"
        val related = candidate.relatedAddress?.let { "; related address $it (client-side observation)" }.orEmpty()
        val mismatch = policy == "relay" && !relay
        Privacy(event, "${event.frame} ${event.pcId}: ${if (relay) "relay infrastructure" else "client ${candidate.type}"} address ${candidate.address}$related; " +
            "effective policy=$policy. ${if (mismatch) "Non-relay candidate observed under relay-only policy; investigate the policy mismatch. " else ""}" +
            "Local observation does not establish signaling disclosure, selected connectivity, or a privacy violation.", mismatch)
    }
    data class Binding(val descriptions: List<TelemetryEvent>, val fingerprints: List<Pair<String, String>>, val limitation: String)
    fun binding(event: TelemetryEvent, events: List<TelemetryEvent>): Binding {
        val role = field(event, "role")
        if (role !in setOf("local", "remote")) return Binding(emptyList(), emptyList(), "Certificate role unknown")
        val generation = field(event, "generation")
        val history = events.filter { it.seq <= event.seq && peer(it) == peer(event) && it.type == "sdp-$role" &&
            (generation.isEmpty() || field(it, "generation") == generation) && field(it, "accepted") != "false" }
        val description = history.maxByOrNull { it.seq } ?: return Binding(emptyList(), emptyList(), "No matching peer/role/generation description")
        val doc = runCatching { SdpDocument.parse(field(description, "sdp")) }.getOrNull()
            ?: return Binding(listOf(description), emptyList(), "Invalid SDP evidence")
        val mids = (objectOf(event)["mids"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
        val sections = doc.media.filter { doc.active(it) && (mids.isEmpty() || it.mid in mids) }
        val groups = sections.map { doc.transportValues(it, "fingerprint").toSet() }.distinct()
        if (groups.size != 1 || groups.firstOrNull().isNullOrEmpty())
            return Binding(listOf(description), emptyList(), "Missing or ambiguous transport/MID fingerprint association")
        if (generation.isEmpty() && history.map { field(it, "sdp") }.distinct().size > 1)
            return Binding(listOf(description), emptyList(), "Legacy certificate lacks negotiation generation")
        val fingerprints = groups.single().mapNotNull { value ->
            val parts = value.split(Regex("\\s+"), limit = 2)
            if (parts.size == 2) parts[0].lowercase() to parts[1] else null
        }
        return Binding(listOf(description), fingerprints, "Matched peer, role, generation and ${if (mids.isEmpty()) "unambiguous transport" else "MID ${mids.joinToString()}"}; remote rejection is not tested")
    }
    fun restartIssues(events: List<TelemetryEvent>): List<String> = events.filter { it.type == "sdp-local" && field(it, "kind") == "offer" }
        .groupBy(::peer).values.flatMap { offers ->
            offers.sortedBy { it.seq }.zipWithNext().mapNotNull { (before, after) ->
                if (field(after, "iceRestart") != "true") return@mapNotNull null
                val old = SdpDocument.parse(field(before, "sdp")).credentials()
                val current = SdpDocument.parse(field(after, "sdp")).credentials()
                val reused = current.filter { (mid, c) -> old[mid]?.let { it.ufrag == c.ufrag || it.password == c.password } == true }.keys
                if (reused.isEmpty()) null else "${after.frame} ${after.pcId}: deliberate ICE restart retained ufrag or password on MID ${reused.joinToString()}; both must rotate."
            }
        }
}
