package webrtc.config

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

/** Persists configuration in the Burp project. Full credentials also appear in telemetry and exports. */
class ConfigStore(private val api: MontoyaApi) {
    val bridgeSessions = webrtc.bridge.BridgeSessions()
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<(WebRtcConfig) -> Unit>()
    fun onChange(listener: (WebRtcConfig) -> Unit): AutoCloseable {
        listeners += listener
        return AutoCloseable { listeners -= listener }
    }
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    private val key = "webrtc.config.v1"

    @Volatile
    var config: WebRtcConfig = load()
        private set

    fun load(): WebRtcConfig {
        val raw = api.persistence().extensionData().getString(key)
        return if (raw.isNullOrBlank()) WebRtcConfig()
        else runCatching {
            json.decodeFromString<WebRtcConfig>(raw).let { decoded ->
                // ScanPlan existed before there were scan controls. Give those projects
                // the all-on defaults once; an explicit empty selection in v2 stays empty.
                val plan = json.parseToJsonElement(raw).jsonObject["scanPlan"]?.jsonObject
                val versioned = if (plan?.containsKey("selectionVersion") != true)
                    decoded.copy(scanPlan = ScanPlan()) else decoded
                // Version 3 added browser, meeting-link and document scans; version 4 the DataChannel runner. A non-empty
                // earlier selection gains them once; an explicit empty selection stays empty.
                val loaded = versioned.scanPlan.let { p ->
                    if (p.selectionVersion >= ScanPlan.CURRENT_VERSION) versioned
                    else versioned.copy(scanPlan = ScanPlan(if (p.enabled.isEmpty()) p.enabled else p.enabled + ScanPlan.addedSince(p.selectionVersion)))
                }
                // Version 0.4 defaulted the SDP fuzzer to 16 fixed cases. Expand that
                // legacy default so existing projects get the new line-mutation pass.
                if (loaded.sdpFuzz.maxCases == 16) loaded.copy(
                    sdpFuzz = loaded.sdpFuzz.copy(maxCases = 300)
                ) else loaded
            }
        }
            .getOrElse {
                api.logging().logToError("[config] parse failed, using defaults: ${it.message}")
                WebRtcConfig()
            }
    }

    fun save(newConfig: WebRtcConfig) {
        if (newConfig == config) return
        api.persistence().extensionData()
            .setString(key, json.encodeToString(WebRtcConfig.serializer(), newConfig))
        config = newConfig
        listeners.forEach { listener -> runCatching { listener(newConfig) } }
    }

    fun toJson(cfg: WebRtcConfig): String = json.encodeToString(WebRtcConfig.serializer(), cfg)
}
