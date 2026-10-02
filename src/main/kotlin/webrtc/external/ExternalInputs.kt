package webrtc.external

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import webrtc.config.WebRtcConfig
import webrtc.telemetry.TelemetryEvent

/** One observed ICE server entry, with the credentials exactly as configured by the app. */
data class ObservedIceServer(
    val urls: List<String>,
    val username: String? = null,
    val credential: String? = null,
    val credentialType: String? = null,
    val frame: String = "",
    val agent: String = "",
    val peer: String = "",
    val observedAt: String = "",
    val source: String = ""
)

/** A parsed ICE server URL (stun/stuns/turn/turns). */
data class IceUrl(val scheme: String, val host: String, val port: Int, val transport: String?) {
    val secure: Boolean get() = scheme.endsWith("s")
    val turn: Boolean get() = scheme.startsWith("turn")
}

/**
 * Passive inputs for the External Tests command builder: only what the extension
 * actually observed (page origins, ICE server configurations including their
 * credentials) plus values the tester enters by hand. Nothing target-specific is
 * hard-coded, and no credential is omitted or masked.
 */
data class ExternalInputs(
    val pageOrigins: List<String>,
    val iceServers: List<ObservedIceServer>
) {
    companion object {
        private val json = Json { ignoreUnknownKeys = true; isLenient = true }
        private val iceUrlRegex = Regex(
            "^(stun|stuns|turn|turns):(\\[[0-9a-fA-F:.]+]|[a-zA-Z0-9._-]+)(?::(\\d+))?(?:\\?transport=(udp|tcp))?$",
            RegexOption.IGNORE_CASE
        )

        fun detect(config: WebRtcConfig, events: List<TelemetryEvent>): ExternalInputs {
            val origins = LinkedHashSet<String>()
            events.mapNotNullTo(origins) { it.frame.takeIf { f -> f.startsWith("http://") || f.startsWith("https://") } }

            val servers = LinkedHashMap<String, ObservedIceServer>()
            events.filter { it.type in setOf("pc-new", "pc-config", "signaling-observation") }.forEach { event ->
                val detail = if (event.type == "signaling-observation") event.raw else field(event, "detail")
                detail?.let {
                    parseIceServersFromDetail(it).forEach { server ->
                        val observed = server.copy(frame = event.frame, agent = field(event, "agent").orEmpty(), peer = event.pcId,
                            observedAt = event.time, source = "event:${event.seq}")
                        servers[listOf(event.frame, observed.agent, event.pcId, field(event, "connectionId"), server.urls.joinToString(","), server.username, server.credential).joinToString("\u0000")] = observed
                    }
                }
            }
            // Config is a first-class observation for the TURN/STUN probe.
            if (config.iceProbe.url.isNotBlank()) {
                val observed = ObservedIceServer(
                    urls = listOf(config.iceProbe.url),
                    username = config.iceProbe.username.ifBlank { null },
                    credential = config.iceProbe.credential.ifBlank { null }, source = "Config M6"
                )
                servers[observed.urls.joinToString(",")] = observed
            }
            return ExternalInputs(origins.toList(), servers.values.toList())
        }

        private fun parseIceServersFromDetail(detail: String): List<ObservedIceServer> {
            val element = runCatching { json.parseToJsonElement(detail) }.getOrNull() ?: return emptyList()
            val array = (element as? JsonObject)?.get("iceServers") as? JsonArray ?: return emptyList()
            return array.mapNotNull { entry ->
                val obj = entry as? JsonObject ?: return@mapNotNull null
                val urls = jsonUrls(obj["urls"]) ?: return@mapNotNull null
                if (urls.isEmpty()) return@mapNotNull null
                ObservedIceServer(
                    urls = urls,
                    username = obj.str("username"),
                    credential = obj.str("credential"),
                    credentialType = obj.str("credentialType")
                )
            }
        }

        private fun jsonUrls(element: JsonElement?): List<String>? = when (element) {
            is JsonPrimitive -> element.contentOrNull?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }
            is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
                .flatMap { it.split(',') }.map { it.trim() }.filter { it.isNotEmpty() }
            else -> null
        }

        fun parseIceUrl(url: String): IceUrl? {
            val match = iceUrlRegex.matchEntire(url.trim()) ?: return null
            val scheme = match.groupValues[1].lowercase()
            val defaultPort = if (scheme.endsWith("s")) 5349 else 3478
            val port = match.groupValues[3].ifEmpty { defaultPort.toString() }.toIntOrNull() ?: return null
            return IceUrl(scheme, match.groupValues[2], port, match.groupValues[4].ifEmpty { "udp" })
        }

        private fun JsonObject.str(key: String): String? =
            (this[key] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }

        private fun field(ev: TelemetryEvent, key: String): String? =
            runCatching { (json.parseToJsonElement(ev.raw).jsonObject[key] as? JsonPrimitive)?.contentOrNull }.getOrNull()
    }
}
