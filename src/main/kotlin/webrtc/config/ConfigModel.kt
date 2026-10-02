package webrtc.config

import kotlinx.serialization.Serializable
import webrtc.tls.TlsScanConfig
import webrtc.protocol.ProtocolScanConfig

/**
 * One named identity = an arbitrary set of request headers (cookies/tokens/auth)
 * plus this identity's values for each identifier key that appears in traffic.
 * Nothing is seeded; the tester supplies these per engagement.
 */
@Serializable
data class IdentityProfile(
    val name: String,
    val headers: Map<String, String> = emptyMap(),
    val identifiers: Map<String, String> = emptyMap(),
    val queryTokens: Map<String, String> = emptyMap(),
    val bodyTokens: Map<String, String> = emptyMap(),
    val origins: List<String> = emptyList()
)

/**
 * Module 0 config. Persisted to the Burp project file. No target-specific
 * constants live in source — everything specific is here, edited per engagement.
 */
@Serializable
data class WebRtcConfig(
    var injectionEnabled: Boolean = false,
    var stripCsp: Boolean = true,
    var hostAllowList: List<String> = emptyList(),
    var bridgeHost: String = "127.0.0.1",
    var bridgePort: Int = 8777,
    var collectPath: String = "/collect",
    var commandPath: String = "/command",
    var agentJsPath: String = "",
    var identities: List<IdentityProfile> = emptyList(),
    var identifierKeys: List<String> = emptyList(),
    var sdpMutation: SdpMutationConfig = SdpMutationConfig(),
    var dataChannelFuzz: DataChannelFuzzConfig = DataChannelFuzzConfig(),
    var iceProbe: IceProbeConfig = IceProbeConfig(),
    var sdpFuzz: SdpFuzzConfig = SdpFuzzConfig(),
    var signalingFlood: SignalingFloodConfig = SignalingFloodConfig(),
    var tlsScan: TlsScanConfig = TlsScanConfig(),
    var scanPlan: ScanPlan = ScanPlan(),
    var protocolScan: ProtocolScanConfig = ProtocolScanConfig(),
    var assessment: webrtc.assessment.AssessmentConfig = webrtc.assessment.AssessmentConfig()
)
