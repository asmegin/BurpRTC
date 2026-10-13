package webrtc.tls

import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import javax.net.ssl.*

/**
 * Built-in TLS listener scanner; needs nothing outside Burp's JVM. Legacy protocol
 * support and cipher suites are measured with hand-built ClientHello messages (the
 * handshake stops at the ServerHello, so no session is established). Certificate
 * trust, hostname and key strength use the JDK's own TLS stack. Output follows the
 * SSLyze runner's schema so Scan All, the report and Burp issues treat both alike.
 */
class JvmTlsScanner(
    private val allowed: () -> Boolean,
    private val cancelled: () -> Boolean,
    private val deadline: Long,
    private val connectTimeoutMs: Int = 5000
) {
    class Stopped(val status: String, message: String) : Exception(message)

    companion object {
        const val ENGINE = "Built-in JVM TLS scanner"
        val SUITES: Map<Int, String> = linkedMapOf(
            0xC02F to "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030 to "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xC02B to "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C to "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xCCA8 to "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9 to "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            0xCCAA to "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0x009E to "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            0x009F to "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0xC027 to "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            0xC028 to "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0xC023 to "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            0xC024 to "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 0xC013 to "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            0xC014 to "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0xC009 to "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            0xC00A to "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 0x0067 to "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            0x006B to "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0x0033 to "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            0x0039 to "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x009C to "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009D to "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x003C to "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x003D to "TLS_RSA_WITH_AES_256_CBC_SHA256", 0x002F to "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035 to "TLS_RSA_WITH_AES_256_CBC_SHA", 0xC012 to "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            0xC008 to "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0x0016 to "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            0x000A to "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0009 to "TLS_RSA_WITH_DES_CBC_SHA",
            0xC011 to "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC007 to "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
            0x0005 to "TLS_RSA_WITH_RC4_128_SHA", 0x0004 to "TLS_RSA_WITH_RC4_128_MD5",
            0x0003 to "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0006 to "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
            0x0008 to "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0034 to "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            0x001B to "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", 0x0018 to "TLS_DH_anon_WITH_RC4_128_MD5",
            0xC018 to "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 0xC016 to "TLS_ECDH_anon_WITH_RC4_128_SHA",
            0xC010 to "TLS_ECDHE_RSA_WITH_NULL_SHA", 0xC006 to "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            0x003B to "TLS_RSA_WITH_NULL_SHA256", 0x0002 to "TLS_RSA_WITH_NULL_SHA", 0x0001 to "TLS_RSA_WITH_NULL_MD5")
        private val WEAK = Regex("NULL|EXPORT|RC4|RC2|3DES|(?:^|_)DES(?:_|$)|anon", RegexOption.IGNORE_CASE)
        val VERSIONS = linkedMapOf(0x0300 to "ssl_3_0", 0x0301 to "tls_1_0", 0x0302 to "tls_1_1", 0x0303 to "tls_1_2")

        /** A ClientHello offering [suites] at [version]; extensions are omitted for SSL 3.0. */
        fun clientHello(host: String, version: Int, suites: List<Int>): ByteArray {
            val body = ByteArrayOutputStream()
            fun u16(v: Int) { body.write(v ushr 8 and 0xFF); body.write(v and 0xFF) }
            u16(version)
            body.write(ByteArray(32).also { SecureRandom().nextBytes(it) })
            body.write(0)
            u16(suites.size * 2 + 2); suites.forEach(::u16); u16(0x00FF) // renegotiation SCSV
            body.write(1); body.write(0)
            if (version >= 0x0301) {
                val ext = ByteArrayOutputStream()
                fun e16(v: Int) { ext.write(v ushr 8 and 0xFF); ext.write(v and 0xFF) }
                fun extension(type: Int, data: ByteArray) { e16(type); e16(data.size); ext.write(data) }
                if (host.isNotEmpty() && !host.contains(':') && !host.all { it.isDigit() || it == '.' }) {
                    val name = host.toByteArray(Charsets.US_ASCII)
                    extension(0x0000, byteArrayOf(((name.size + 3) ushr 8).toByte(), (name.size + 3).toByte(), 0,
                        (name.size ushr 8).toByte(), name.size.toByte()) + name)
                }
                extension(0x000a, byteArrayOf(0, 8, 0, 0x1d, 0, 0x17, 0, 0x18, 0, 0x19))
                extension(0x000b, byteArrayOf(1, 0))
                if (version >= 0x0303) {
                    val algorithms = listOf(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203)
                    extension(0x000d, byteArrayOf(0, (algorithms.size * 2).toByte()) + algorithms.flatMap { listOf((it ushr 8).toByte(), it.toByte()) })
                }
                val bytes = ext.toByteArray(); u16(bytes.size); body.write(bytes)
            }
            val hello = body.toByteArray()
            val handshake = byteArrayOf(1, (hello.size ushr 16).toByte(), (hello.size ushr 8).toByte(), hello.size.toByte()) + hello
            val recordVersion = minOf(version, 0x0301)
            return byteArrayOf(0x16, (recordVersion ushr 8).toByte(), recordVersion.toByte(), (handshake.size ushr 8).toByte(), handshake.size.toByte()) + handshake
        }

        /** (version, cipher) from the first ServerHello, or null on alert / close / other message. */
        fun parseServerHello(input: DataInputStream): Pair<Int, Int>? {
            val handshake = ByteArrayOutputStream()
            while (handshake.size() < 42) {
                val type = input.read(); if (type < 0) return null
                input.readUnsignedShort(); val length = input.readUnsignedShort()
                if (length > 18432) return null
                val fragment = ByteArray(length).also(input::readFully)
                if (type != 0x16) return null
                handshake.write(fragment)
            }
            val data = handshake.toByteArray()
            if (data[0].toInt() != 2) return null
            val version = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
            val sessionLength = data[38].toInt() and 0xFF
            if (data.size < 41 + sessionLength) return null
            val cipher = ((data[39 + sessionLength].toInt() and 0xFF) shl 8) or (data[40 + sessionLength].toInt() and 0xFF)
            return version to cipher
        }
    }

    private var handshakes = 0
    private fun guard() {
        if (cancelled()) throw Stopped("cancelled", "TLS task stopped")
        if (!allowed()) throw Stopped("blocked", "TLS task stopped: scope or injection/allow-list permission was removed")
        if (System.nanoTime() >= deadline) throw Stopped("timeout", "TLS task exceeded its time budget")
        if (++handshakes > 120) throw Stopped("partial", "Handshake budget exhausted")
    }
    private fun timeout() = ((deadline - System.nanoTime()) / 1_000_000).coerceIn(500, connectTimeoutMs.toLong()).toInt()

    private fun probe(host: String, port: Int, version: Int, suites: List<Int>): Pair<Int, Int>? {
        guard()
        return Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), timeout()); socket.soTimeout = timeout()
            socket.getOutputStream().apply { write(clientHello(host, version, suites)); flush() }
            runCatching { parseServerHello(DataInputStream(socket.getInputStream())) }.getOrNull()
        }
    }

    private val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    })

    private fun jdkHandshake(host: String, port: Int, protocols: Array<String>, verify: Boolean): SSLSession {
        guard()
        val context = SSLContext.getInstance("TLS").apply { init(null, if (verify) null else trustAll, SecureRandom()) }
        val raw = Socket().apply { connect(InetSocketAddress(host, port), timeout()); soTimeout = timeout() }
        (context.socketFactory.createSocket(raw, host, port, true) as SSLSocket).use { socket ->
            socket.enabledProtocols = protocols.filter { it in socket.supportedProtocols }.toTypedArray()
            socket.sslParameters = socket.sslParameters.apply { if (verify) endpointIdentificationAlgorithm = "HTTPS" }
            socket.startHandshake()
            return socket.session
        }
    }

    fun scan(host: String, port: Int): JsonObject {
        val checks = mutableListOf<JsonObject>(); val findings = mutableListOf<JsonObject>()
        val raw = buildJsonObject {}.toMutableMap()
        fun check(name: String, status: String, summary: String) { checks += buildJsonObject { put("name", name); put("status", status); put("summary", summary) } }
        fun finding(level: String, text: String, check: String? = null) { findings += buildJsonObject { put("level", level); check?.let { put("check", it) }; put("text", text) } }
        var stopped: Stopped? = null
        try {
            val protocols = buildJsonObject {}.toMutableMap()
            for ((version, name) in VERSIONS) {
                val hello = runCatching { probe(host, port, version, SUITES.keys.toList()) }.getOrElse { if (it is Stopped) throw it; null }
                val accepted = hello != null && hello.first == version
                protocols[name] = JsonPrimitive(accepted)
                if (version < 0x0303) {
                    check("${name}_cipher_suites", "completed", "${name.replace('_', ' ')} cipher suites: completed; " +
                        if (accepted) "1 accepted cipher suite(s) (${SUITES[hello!!.second] ?: "0x%04x".format(hello.second)}; enumeration limited to the preferred suite)" else "0 accepted cipher suite(s)")
                    if (accepted) finding("finding", "${name.replace('_', ' ')} accepted by the listener", "${name}_cipher_suites")
                }
            }
            // Enumerate TLS 1.2 suites by removing each accepted suite and asking again.
            val remaining = SUITES.keys.toMutableList(); val accepted12 = mutableListOf<String>()
            while (remaining.isNotEmpty()) {
                val hello = runCatching { probe(host, port, 0x0303, remaining) }.getOrElse { if (it is Stopped) throw it; null } ?: break
                if (hello.first != 0x0303 || hello.second !in remaining) break
                remaining.remove(hello.second); accepted12 += SUITES.getValue(hello.second)
            }
            raw["tls_1_2_accepted"] = JsonArray(accepted12.map(::JsonPrimitive))
            check("tls_1_2_cipher_suites", "completed", "tls 1 2 cipher suites: completed; ${accepted12.size} accepted cipher suite(s)")
            accepted12.filter { WEAK.containsMatchIn(it) }.takeIf { it.isNotEmpty() }?.let {
                finding("finding", "Weak cipher suite(s) accepted: ${it.joinToString(", ")}", "tls_1_2_cipher_suites")
            }
            accepted12.filter { it.startsWith("TLS_RSA_") && !WEAK.containsMatchIn(it) }.takeIf { it.isNotEmpty() }?.let {
                finding("warn", "Suites without forward secrecy accepted: ${it.joinToString(", ")}", "tls_1_2_cipher_suites")
            }
            val tls13 = runCatching { jdkHandshake(host, port, arrayOf("TLSv1.3"), false) }.getOrElse { if (it is Stopped) throw it; null }
            protocols["tls_1_3"] = JsonPrimitive(tls13 != null)
            check("tls_1_3_cipher_suites", "completed", "tls 1 3 cipher suites: completed; " + (tls13?.let { "1 accepted cipher suite(s) (${it.cipherSuite})" } ?: "0 accepted cipher suite(s)"))
            raw["protocols"] = JsonObject(protocols)
            if (protocols.values.none { (it as JsonPrimitive).boolean }) finding("warn", "No TLS handshake succeeded; the listener may not speak TLS on this port")

            val session = runCatching { jdkHandshake(host, port, arrayOf("TLSv1.3", "TLSv1.2"), false) }.getOrElse { if (it is Stopped) throw it; null }
            val chain = session?.peerCertificates?.filterIsInstance<X509Certificate>().orEmpty()
            if (chain.isEmpty()) check("certificate_info", "error", "certificate info: error; no certificate received")
            else {
                val leaf = chain.first(); val now = Instant.now()
                val trust = runCatching { jdkHandshake(host, port, arrayOf("TLSv1.3", "TLSv1.2"), true); "trusted" }
                    .getOrElse { if (it is Stopped) throw it; it.message ?: it.javaClass.simpleName }
                raw["certificate"] = buildJsonObject {
                    put("subject", leaf.subjectX500Principal.name); put("issuer", leaf.issuerX500Principal.name)
                    put("notBefore", leaf.notBefore.toInstant().toString()); put("notAfter", leaf.notAfter.toInstant().toString())
                    put("signatureAlgorithm", leaf.sigAlgName); put("validation", trust)
                    put("subjectAlternativeNames", JsonArray(runCatching { leaf.subjectAlternativeNames?.map { JsonPrimitive(it[1].toString()) } }.getOrNull().orEmpty()))
                }
                check("certificate_info", "completed", "certificate info: completed; 1 certificate deployment(s)")
                if (trust != "trusted") finding("warn", "Certificate validation (trust store and hostname) failed: $trust")
                if (leaf.notAfter.toInstant() < now || leaf.notBefore.toInstant() > now) finding("warn", "Listener certificate is outside its validity period")
                when (val key = leaf.publicKey) {
                    is RSAPublicKey -> if (key.modulus.bitLength() < 2048) finding("warn", "Listener certificate has a weak public key: ${key.modulus.bitLength()} bits")
                    is ECPublicKey -> if (key.params.order.bitLength() < 256) finding("warn", "Listener certificate has a weak public key: ${key.params.order.bitLength()} bits")
                }
                if (chain.dropLast(1).any { it.sigAlgName.contains("SHA1", true) }) finding("warn", "Certificate chain contains a SHA-1 signature")
            }
        } catch (e: Stopped) { stopped = e }
        raw["handshakes"] = JsonPrimitive(handshakes)
        raw["limitations"] = JsonPrimitive("SSL 2.0, compression, renegotiation and vulnerability probes (Heartbleed, ROBOT, CCS) need the optional SSLyze engine. Legacy-version cipher enumeration reports the preferred suite only.")
        return buildJsonObject {
            put("schema", 1); put("engine", ENGINE); put("hostname", host); put("port", port)
            put("status", when { stopped != null && checks.isEmpty() -> "failed"; stopped != null -> "partial"; else -> "completed" })
            stopped?.let { put("error", it.message) }
            put("checks", JsonArray(checks)); put("findings", JsonArray(findings)); put("raw", JsonObject(raw))
        }
    }
}
