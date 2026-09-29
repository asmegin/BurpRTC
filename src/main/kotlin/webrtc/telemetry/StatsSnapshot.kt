package webrtc.telemetry

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

/**
 * A bounded `getStats()` snapshot captured by the agent (event `stats-snapshot`).
 * This is evidence from the browser's own statistics API: transport/DTLS roles,
 * the chosen ICE pair, RTP streams in use, and candidates. It never proves that
 * media reached a peer; it describes what the local engine reports.
 */
data class RtpStream(
    val direction: String,
    val kind: String,
    val ssrc: String,
    val payloadType: Int?,
    val packets: Long?,
    val bytes: Long?,
    val packetsLost: Long?,
    val jitter: Double?,
    val codec: String
)

data class CandidateEntry(
    val role: String,
    val type: String,
    val protocol: String,
    val address: String,
    val port: Int?
)

data class StatsSnapshot(
    val pcId: String,
    val dtlsRole: String,
    val iceRole: String,
    val pair: String,
    val rtp: List<RtpStream>,
    val candidates: List<CandidateEntry>,
    val truncated: Boolean
) {
    companion object {
        private val json = Json { ignoreUnknownKeys = true; isLenient = true }

        fun parse(raw: String): StatsSnapshot? = runCatching {
            val obj = json.parseToJsonElement(raw).jsonObject
            val transport = obj["transport"] as? JsonObject
            StatsSnapshot(
                pcId = obj.str("pc"),
                dtlsRole = transport?.str("dtlsRole").orEmpty(),
                iceRole = transport?.str("iceRole").orEmpty(),
                pair = obj.str("pair"),
                rtp = (obj["rtp"] as? JsonArray).orEmpty().mapNotNull { element ->
                    val r = element as? JsonObject ?: return@mapNotNull null
                    RtpStream(
                        direction = r.str("direction"),
                        kind = r.str("kind"),
                        ssrc = r.str("ssrc"),
                        payloadType = r.int("payloadType"),
                        packets = r.long("packets"),
                        bytes = r.long("bytes"),
                        packetsLost = r.long("packetsLost"),
                        jitter = r.dbl("jitter"),
                        codec = r.str("codec")
                    )
                },
                candidates = (obj["candidates"] as? JsonArray).orEmpty().mapNotNull { element ->
                    val c = element as? JsonObject ?: return@mapNotNull null
                    CandidateEntry(
                        role = c.str("role"),
                        type = c.str("type"),
                        protocol = c.str("protocol"),
                        address = c.str("address"),
                        port = c.int("port")
                    )
                },
                truncated = (obj["truncated"] as? JsonPrimitive)?.booleanOrNull == true
            )
        }.getOrNull()

        private fun JsonObject.str(key: String): String = (this[key] as? JsonPrimitive)?.contentOrNull.orEmpty()
        private fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull
        private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull
        private fun JsonObject.dbl(key: String): Double? = (this[key] as? JsonPrimitive)?.doubleOrNull
    }
}
