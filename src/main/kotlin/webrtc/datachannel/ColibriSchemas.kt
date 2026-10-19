package webrtc.datachannel

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject

/**
 * Jitsi Videobridge bridge-channel message classes, from the bridge's message definitions
 * (jitsi-videobridge BridgeChannelMessage). Generations: 1 = endpoint-based (2.1 and earlier),
 * 2 = source names (2.2), 3 = SSRC-rewriting source maps (2.3+). Observed messages always win
 * over these examples; examples are only used for classes the application has not sent.
 */
object ColibriSchemas {
    const val PROTOCOL = "http://jitsi.org/protocols/colibri"

    enum class Direction { CLIENT_TO_BRIDGE, BRIDGE_TO_CLIENT, BOTH }

    data class Field(val name: String, val type: String, val identity: Boolean = false)

    data class MessageClass(
        val name: String,
        val direction: Direction,
        /** The bridge relays it to other endpoints (with "from" set by the bridge). */
        val forwarded: Boolean,
        val fields: List<Field>,
        val example: String,
        val since: Int = 1,
        val until: Int = 3
    ) {
        fun inGeneration(g: Int) = g in since..until
        val identityFields: List<String> get() = fields.filter { it.identity }.map { it.name }
    }

    val classes = listOf(
        MessageClass("ClientHello", Direction.CLIENT_TO_BRIDGE, false, emptyList(), """{"colibriClass":"ClientHello"}"""),
        MessageClass("ServerHello", Direction.BRIDGE_TO_CLIENT, false, listOf(Field("version", "string")), """{"colibriClass":"ServerHello","version":"2.3"}"""),
        MessageClass("EndpointMessage", Direction.BOTH, true,
            listOf(Field("to", "string", true), Field("from", "string", true), Field("msgPayload", "object")),
            """{"colibriClass":"EndpointMessage","to":"","msgPayload":{"type":"wrtc-test"}}"""),
        MessageClass("EndpointStats", Direction.BOTH, true,
            listOf(Field("from", "string", true), Field("bitrate", "object"), Field("packetLoss", "object"), Field("connectionQuality", "number"),
                Field("jvbRTT", "number"), Field("serverRegion", "string"), Field("maxEnabledResolution", "integer"), Field("codec", "object")),
            """{"colibriClass":"EndpointStats","bitrate":{"audio":{"upload":24,"download":30},"video":{"upload":500,"download":800},"upload":524,"download":830},"packetLoss":{"total":0,"download":0,"upload":0},"connectionQuality":100,"jvbRTT":20,"serverRegion":"","maxEnabledResolution":720}"""),
        MessageClass("LastNChangedEvent", Direction.CLIENT_TO_BRIDGE, false, listOf(Field("lastN", "integer")), """{"colibriClass":"LastNChangedEvent","lastN":5}"""),
        MessageClass("ReceiverVideoConstraints", Direction.CLIENT_TO_BRIDGE, false,
            listOf(Field("lastN", "integer"), Field("selectedEndpoints", "array", true), Field("onStageEndpoints", "array", true),
                Field("defaultConstraints", "object"), Field("constraints", "object")),
            """{"colibriClass":"ReceiverVideoConstraints","lastN":5,"selectedEndpoints":[],"onStageEndpoints":[],"defaultConstraints":{"maxHeight":180},"constraints":{}}""",
            until = 1),
        MessageClass("ReceiverVideoConstraints", Direction.CLIENT_TO_BRIDGE, false,
            listOf(Field("lastN", "integer"), Field("selectedSources", "array", true), Field("onStageSources", "array", true),
                Field("defaultConstraints", "object"), Field("constraints", "object")),
            """{"colibriClass":"ReceiverVideoConstraints","lastN":5,"selectedSources":[],"onStageSources":[],"defaultConstraints":{"maxHeight":180},"constraints":{}}""",
            since = 2),
        MessageClass("VideoTypeMessage", Direction.CLIENT_TO_BRIDGE, true, listOf(Field("videoType", "string")),
            """{"colibriClass":"VideoTypeMessage","videoType":"camera"}""", until = 1),
        MessageClass("SourceVideoTypeMessage", Direction.CLIENT_TO_BRIDGE, true,
            listOf(Field("sourceName", "string", true), Field("videoType", "string")),
            """{"colibriClass":"SourceVideoTypeMessage","sourceName":"{self}-v0","videoType":"camera"}""", since = 2),
        MessageClass("DominantSpeakerEndpointChangeEvent", Direction.BRIDGE_TO_CLIENT, false,
            listOf(Field("dominantSpeakerEndpoint", "string", true), Field("previousSpeakers", "array"), Field("silence", "boolean")),
            """{"colibriClass":"DominantSpeakerEndpointChangeEvent","dominantSpeakerEndpoint":"{victim}","previousSpeakers":[],"silence":false}"""),
        MessageClass("EndpointConnectivityStatusChangeEvent", Direction.BRIDGE_TO_CLIENT, false,
            listOf(Field("endpoint", "string", true), Field("active", "string")),
            """{"colibriClass":"EndpointConnectivityStatusChangeEvent","endpoint":"{victim}","active":"false"}"""),
        MessageClass("ForwardedEndpointsMessage", Direction.BRIDGE_TO_CLIENT, false, listOf(Field("lastNEndpoints", "array", true)),
            """{"colibriClass":"ForwardedEndpointsMessage","lastNEndpoints":[]}""", until = 1),
        MessageClass("ForwardedSources", Direction.BRIDGE_TO_CLIENT, false, listOf(Field("forwardedSources", "array", true)),
            """{"colibriClass":"ForwardedSources","forwardedSources":[]}""", since = 2),
        MessageClass("SenderVideoConstraints", Direction.BRIDGE_TO_CLIENT, false, listOf(Field("videoConstraints", "object")),
            """{"colibriClass":"SenderVideoConstraints","videoConstraints":{"idealHeight":0}}""", until = 1),
        MessageClass("SenderSourceConstraints", Direction.BRIDGE_TO_CLIENT, false,
            listOf(Field("sourceName", "string", true), Field("maxHeight", "integer")),
            """{"colibriClass":"SenderSourceConstraints","sourceName":"{victim}-v0","maxHeight":0}""", since = 2),
        MessageClass("VideoSourcesMap", Direction.BRIDGE_TO_CLIENT, false, listOf(Field("mappedSources", "array", true)),
            """{"colibriClass":"VideoSourcesMap","mappedSources":[{"source":"{victim}-v0","owner":"{victim}","ssrc":1,"rtx":2,"videoType":"CAMERA"}]}""", since = 3),
        MessageClass("AudioSourcesMap", Direction.BRIDGE_TO_CLIENT, false, listOf(Field("mappedSources", "array", true)),
            """{"colibriClass":"AudioSourcesMap","mappedSources":[{"source":"{victim}-a0","owner":"{victim}","ssrc":3}]}""", since = 3),
        MessageClass("ConnectionStats", Direction.BRIDGE_TO_CLIENT, false, listOf(Field("estimatedDownlinkBandwidth", "number")),
            """{"colibriClass":"ConnectionStats","estimatedDownlinkBandwidth":1000000}""")
    )

    data class Selection(val generation: Int, val source: String) {
        val label: String get() = "Colibri generation $generation (${when (generation) { 1 -> "endpoint-based, JVB 2.1 and earlier"; 2 -> "source names, JVB 2.2"; else -> "source maps, JVB 2.3+" }}) — $source"
    }

    /** Major/minor from strings such as "2.3-105-ge155b81e" or "2.1.1". */
    fun parseVersion(text: String?): Pair<Int, Int>? =
        Regex("(\\d+)\\.(\\d+)").find(text.orEmpty())?.let { it.groupValues[1].toInt() to it.groupValues[2].toInt() }

    fun generationFor(version: Pair<Int, Int>): Int = when {
        version.first < 2 || (version.first == 2 && version.second <= 1) -> 1
        version.first == 2 && version.second == 2 -> 2
        else -> 3
    }

    /** Configured version, then ServerHello, then observed class names; otherwise the current generation (assumed). */
    fun select(configured: String, serverHello: String?, observed: Set<String>): Selection {
        parseVersion(configured)?.let { return Selection(generationFor(it), "configured version $configured") }
        parseVersion(serverHello)?.let { return Selection(generationFor(it), "ServerHello version $serverHello") }
        return when {
            observed.any { it in setOf("VideoSourcesMap", "AudioSourcesMap") } -> Selection(3, "inferred from observed source maps")
            observed.any { it in setOf("ForwardedSources", "SenderSourceConstraints", "SourceVideoTypeMessage") } -> Selection(2, "inferred from observed source-name messages")
            observed.any { it in setOf("ForwardedEndpointsMessage", "SenderVideoConstraints", "VideoTypeMessage") } -> Selection(1, "inferred from observed endpoint-based messages")
            else -> Selection(3, "assumed (no version or distinguishing class observed)")
        }
    }

    fun forGeneration(g: Int) = classes.filter { it.inGeneration(g) }
    fun byName(name: String, g: Int) = classes.firstOrNull { it.name == name && it.inGeneration(g) } ?: classes.firstOrNull { it.name == name }
    fun known(name: String) = classes.any { it.name == name }

    private val json = Json { ignoreUnknownKeys = true }
    fun colibriClass(text: String): String? = runCatching {
        (json.parseToJsonElement(text).jsonObject["colibriClass"] as? JsonPrimitive)?.contentOrNull
    }.getOrNull()
    fun parseObject(text: String): JsonObject? = runCatching { json.parseToJsonElement(text) as? JsonObject }.getOrNull()
}
