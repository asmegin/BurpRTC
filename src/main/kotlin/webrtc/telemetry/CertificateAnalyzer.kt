package webrtc.telemetry

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.security.MessageDigest

/**
 * DTLS certificate + fingerprint binding analysis (T2). The agent emits each
 * certificate once as a `dtls-cert` event carrying the DER bytes (base64). Here
 * we parse the X.509, compute the SHA-256 fingerprint and compare it with the
 * `a=fingerprint` in the captured SDP (RFC 8827 binds the DTLS certificate to the
 * signaling). A local certificate is normal for WebRTC DTLS; the meaningful
 * checks are binding agreement, validity, and key strength.
 */
object CertificateAnalyzer {

    data class CertificateInfo(
        val role: String,
        val declaredAlgorithm: String,
        val declaredFingerprint: String,
        val subject: String?,
        val issuer: String?,
        val notBefore: Instant?,
        val notAfter: Instant?,
        val keyAlgorithm: String?,
        val keySize: Int?,
        val selfSigned: Boolean,
        val computedFingerprint: String?,
        val parseError: String?
    )

    private val pemHeader = Regex("-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\\s")

    fun parse(role: String, algorithm: String, fingerprint: String, base64Der: String): CertificateInfo {
        val cleaned = base64Der.replace(pemHeader, "")
        val der = runCatching { Base64.getDecoder().decode(cleaned) }.getOrNull()
        if (der == null || der.isEmpty()) return unparsed(role, algorithm, fingerprint, "certificate bytes were not valid base64")
        val cert = runCatching {
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }.getOrNull() ?: return unparsed(role, algorithm, fingerprint, "certificate could not be parsed as X.509")

        val (keyAlgorithm, keySize) = runCatching {
            when (val key = cert.publicKey) {
                is RSAPublicKey -> "RSA" to key.modulus.bitLength()
                is ECPublicKey -> "EC" to key.params.order.bitLength()
                else -> (key.algorithm ?: "?") to null
            }
        }.getOrDefault("?" to null)

        return CertificateInfo(
            role = role,
            declaredAlgorithm = algorithm,
            declaredFingerprint = fingerprint,
            subject = cert.subjectX500Principal?.name,
            issuer = cert.issuerX500Principal?.name,
            notBefore = runCatching { cert.notBefore.toInstant() }.getOrNull(),
            notAfter = runCatching { cert.notAfter.toInstant() }.getOrNull(),
            keyAlgorithm = keyAlgorithm,
            keySize = keySize,
            selfSigned = cert.subjectX500Principal == cert.issuerX500Principal,
            computedFingerprint = sha256Fingerprint(der),
            parseError = null
        )
    }

    private fun unparsed(role: String, algorithm: String, fingerprint: String, error: String) =
        CertificateInfo(role, algorithm, fingerprint, null, null, null, null, null, null, false, null, error)

    /** Uppercase, colon-separated SHA-256 hex of the DER bytes. */
    fun sha256Fingerprint(der: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(der)
        return digest.joinToString(":") { "%02X".format(it) }
    }

    fun normalizeFingerprint(value: String): String =
        value.replace(":", "").replace(Regex("\\s"), "").uppercase()

    /** Values of every `a=fingerprint:<algo> <value>` line in the captured SDP texts. */
    fun sdpFingerprints(sdpTexts: List<String>): List<Pair<String, String>> {
        val regex = Regex("""(?im)^a=fingerprint:(\S+)\s+(\S+)""")
        return sdpTexts.flatMap { sdp -> regex.findAll(sdp).map { it.groupValues[1].lowercase() to it.groupValues[2] } }
            .distinct()
    }

    /**
     * Plain-English findings for parsed certificates against the SDP fingerprints.
     * A binding mismatch is a finding; expired/weak certificates are warnings.
     */
    fun analyze(certificates: List<CertificateInfo>, fingerprints: List<Pair<String, String>>, now: Instant = Instant.now()): List<Pair<String, Boolean>> {
        val out = mutableListOf<Pair<String, Boolean>>() // text to isFinding
        for (cert in certificates) {
            val label = "${cert.role.ifBlank { "?" }} certificate"
            if (cert.parseError != null) {
                out += "DTLS $label could not be analysed: ${cert.parseError}." to false
                continue
            }
            cert.keySize?.let { size ->
                val weak = (cert.keyAlgorithm == "RSA" && size < 2048) || (cert.keyAlgorithm == "EC" && size < 256)
                if (weak) out += "DTLS $label uses a weak ${cert.keyAlgorithm} key (${size} bits)." to false
            }
            cert.notAfter?.let { notAfter ->
                if (notAfter.isBefore(now)) out += "DTLS $label expired on $notAfter." to false
                else if (Duration.between(now, notAfter) < Duration.ofDays(7))
                    out += "DTLS $label expires within 7 days ($notAfter)." to false
            }
            // Binding: at least one SDP fingerprint must match the computed SHA-256.
            val sha256 = fingerprints.filter { it.first in setOf("sha-256", "sha256") }.map { it.second }
            if (cert.computedFingerprint != null && sha256.isNotEmpty()) {
                val declared = sha256.map { normalizeFingerprint(it) }
                if (normalizeFingerprint(cert.computedFingerprint) !in declared)
                    out += "DTLS $label fingerprint does not match the SDP a=fingerprint — the signaling does not bind this certificate (RFC 8827)." to true
            }
        }
        if (certificates.any { it.role == "remote" } && fingerprints.none { it.first in setOf("sha-256", "sha256") })
            out += "A DTLS certificate was observed but no SDP sha-256 a=fingerprint was captured to bind it against." to false
        return out
    }
}
