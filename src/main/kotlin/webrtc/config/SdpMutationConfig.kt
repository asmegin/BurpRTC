package webrtc.config

import kotlinx.serialization.Serializable

@Serializable
data class SdpTextRule(val find: String = "", val replacement: String = "")

/** Rules run in order: remove attributes, set media direction, literal replacement. */
@Serializable
data class SdpMutationConfig(
    val enabled: Boolean = false,
    val target: String = "remote",
    val pcId: String = "",
    val removeFingerprint: Boolean = false,
    val removeCandidates: Boolean = false,
    val mediaDirection: String = "unchanged",
    // Kept for reading projects saved before multiple text rules were added.
    val find: String = "",
    val replacement: String = "",
    val rules: List<SdpTextRule> = emptyList()
) {
    fun effectiveRules(): List<SdpTextRule> = when {
        rules.isNotEmpty() -> rules
        find.isNotEmpty() -> listOf(SdpTextRule(find, replacement))
        else -> emptyList()
    }

    init {
        require(target in listOf("local", "remote", "both")) { "Invalid SDP target" }
        require(mediaDirection in listOf("unchanged", "sendrecv", "sendonly", "recvonly", "inactive")) {
            "Invalid media direction"
        }
        require(find.length <= 4096 && replacement.length <= 4096) { "Replacement text is limited to 4096 characters" }
        require(rules.size <= 20) { "Use no more than 20 text rules" }
        require(rules.all { it.find.length <= 4096 && it.replacement.length <= 4096 }) {
            "Each match and replacement is limited to 4096 characters"
        }
        require(rules.sumOf { it.find.length + it.replacement.length } <= 81920) {
            "Combined text rules are limited to 80 KiB"
        }
        require(!enabled || removeFingerprint || removeCandidates || mediaDirection != "unchanged" || effectiveRules().any { it.find.isNotEmpty() }) {
            "Select a mutation or enter text to replace before enabling M3"
        }
    }
}
