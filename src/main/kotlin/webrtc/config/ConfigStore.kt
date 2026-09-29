package webrtc.config

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.Json

/** Loads/saves Module 0 config in the Burp project file. Credentials live only here. */
class ConfigStore(private val api: MontoyaApi) {
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
            json.decodeFromString<WebRtcConfig>(raw).let { loaded ->
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
        api.persistence().extensionData()
            .setString(key, json.encodeToString(WebRtcConfig.serializer(), newConfig))
        config = newConfig
    }

    fun toJson(cfg: WebRtcConfig): String = json.encodeToString(WebRtcConfig.serializer(), cfg)
}
