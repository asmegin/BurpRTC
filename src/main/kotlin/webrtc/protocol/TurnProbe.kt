package webrtc.protocol

import kotlinx.serialization.json.*
import webrtc.assessment.TestEvidence
import webrtc.assessment.TestOutcome
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.*
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** STUN message encoding/decoding (RFC 8489) with long-term-credential MESSAGE-INTEGRITY. */
object Stun {
    const val COOKIE = 0x2112A442
    const val BINDING = 0x0001; const val ALLOCATE = 0x0003; const val REFRESH = 0x0004
    const val SEND = 0x0016; const val DATA = 0x0017; const val PERMISSION = 0x0008; const val CHANNEL_BIND = 0x0009
    const val USERNAME = 0x0006; const val INTEGRITY = 0x0008; const val ERROR = 0x0009; const val CHANNEL = 0x000C
    const val LIFETIME = 0x000D; const val PEER = 0x0012; const val DATA_ATTR = 0x0013; const val REALM = 0x0014
    const val NONCE = 0x0015; const val RELAYED = 0x0016; const val TRANSPORT = 0x0019; const val SOFTWARE = 0x8022
    const val ALTERNATE = 0x8023

    data class Message(val type: Int, val transaction: ByteArray, val attrs: List<Pair<Int, ByteArray>>, val integrity: Boolean?) {
        fun first(tag: Int): ByteArray = attrs.firstOrNull { it.first == tag }?.second ?: ByteArray(0)
        fun errorCode(): Int? = first(ERROR).takeIf { it.size >= 4 }?.let { (it[2].toInt() and 7) * 100 + (it[3].toInt() and 0xFF) }
    }

    fun attribute(type: Int, value: ByteArray): ByteArray = ByteBuffer.allocate(4 + value.size + (4 - value.size % 4) % 4)
        .putShort(type.toShort()).putShort(value.size.toShort()).put(value).array()

    fun encode(type: Int, transaction: ByteArray, attrs: List<Pair<Int, ByteArray>>, key: ByteArray? = null): ByteArray {
        val body = ByteArrayOutputStream().apply { attrs.forEach { write(attribute(it.first, it.second)) } }.toByteArray()
        fun header(length: Int) = ByteBuffer.allocate(20).putShort(type.toShort()).putShort(length.toShort()).putInt(COOKIE).put(transaction).array()
        if (key == null) return header(body.size) + body
        val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }.doFinal(header(body.size + 24) + body)
        return header(body.size + 24) + body + attribute(INTEGRITY, mac)
    }

    fun decode(data: ByteArray, expected: ByteArray? = null, key: ByteArray? = null): Message {
        require(data.size >= 20) { "Truncated STUN header" }
        val buffer = ByteBuffer.wrap(data)
        val type = buffer.short.toInt() and 0xFFFF; val length = buffer.short.toInt() and 0xFFFF; val cookie = buffer.int
        val transaction = data.copyOfRange(8, 20)
        require(cookie == COOKIE && type and 0xC000 == 0 && length % 4 == 0 && data.size == 20 + length) { "Invalid STUN framing" }
        require(expected == null || expected.contentEquals(transaction)) { "STUN transaction mismatch" }
        val attrs = mutableListOf<Pair<Int, ByteArray>>(); var offset = 20; var integrity: Boolean? = null
        while (offset < data.size) {
            require(offset + 4 <= data.size) { "Truncated attribute" }
            val tag = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            val size = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
            val end = offset + 4 + size
            require(end <= data.size) { "Attribute exceeds message" }
            val value = data.copyOfRange(offset + 4, end)
            if (tag == INTEGRITY) {
                require(integrity == null && size == 20) { "Invalid duplicate MESSAGE-INTEGRITY" }
                val header = data.copyOfRange(0, 2) + ByteBuffer.allocate(2).putShort((end - 20).toShort()).array() + data.copyOfRange(4, 20)
                integrity = key != null && MessageDigest.isEqual(
                    Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }.doFinal(header + data.copyOfRange(20, offset)), value)
            }
            // Never interpret semantic attributes beyond the integrity boundary.
            if (integrity == null) attrs += tag to value
            offset = end + (4 - size % 4) % 4
        }
        return Message(type, transaction, attrs, integrity)
    }

    fun xorAddress(address: InetAddress, port: Int, transaction: ByteArray): ByteArray {
        val raw = address.address
        val mask = ByteBuffer.allocate(4).putInt(COOKIE).array() + transaction
        return byteArrayOf(0, if (raw.size == 4) 1 else 2) + ByteBuffer.allocate(2).putShort((port xor (COOKIE ushr 16)).toShort()).array() +
            ByteArray(raw.size) { (raw[it].toInt() xor mask[it].toInt()).toByte() }
    }

    fun decodeAddress(value: ByteArray, transaction: ByteArray): Pair<InetAddress, Int> {
        require(value.size >= 4 && value[1].toInt() in 1..2) { "Invalid XOR address" }
        val size = if (value[1].toInt() == 1) 4 else 16
        require(value.size == size + 4) { "Invalid XOR address length" }
        val mask = ByteBuffer.allocate(4).putInt(COOKIE).array() + transaction
        val port = (((value[2].toInt() and 0xFF) shl 8) or (value[3].toInt() and 0xFF)) xor (COOKIE ushr 16)
        return InetAddress.getByAddress(ByteArray(size) { (value[4 + it].toInt() xor mask[it].toInt()).toByte() }) to port
    }
}

/**
 * Built-in STUN/TURN runner (TRN-01/02/04/05/07). Runs inside Burp with no external
 * runtime. Every connect and send is re-authorized for both the named listener and
 * the pinned IP; redirects and alternate servers are recorded, never followed.
 * Forwarding tests use the tester's UDP echo peer when supplied, otherwise a second
 * allocation on the same server acts as the receiving peer.
 */
class TurnProbe(private val allowsLeg: (String, String, Int) -> Boolean, private val cancelled: () -> Boolean) {
    class Blocked(message: String) : Exception(message)
    data class Credential(val condition: String, val username: String, val password: String)
    private val random = SecureRandom()
    private fun now() = Instant.now().toString()

    private class Budget(seconds: Int) {
        val deadline = System.nanoTime() + seconds * 1_000_000_000L
        var messages = 200; var bytes = 1_048_576L
        fun check(size: Int = 0) {
            if (System.nanoTime() >= deadline) throw java.util.concurrent.TimeoutException("Execution budget expired")
            messages--; bytes -= size
            require(messages >= 0 && bytes >= 0) { "Packet/message/byte budget exhausted" }
        }
        fun timeoutMs(): Int = ((deadline - System.nanoTime()) / 1_000_000).coerceIn(100, 3000).toInt()
    }

    private inner class Connection(val target: ProtocolTarget, val budget: Budget) : AutoCloseable {
        val address: InetAddress = InetAddress.getByName(target.host)
        private var udp: DatagramSocket? = null
        private var stream: Socket? = null
        private var input: InputStream? = null
        private var output: OutputStream? = null
        init {
            permit()
            if (target.transport == "udp") udp = DatagramSocket().apply { connect(address, target.port) }
            else {
                val socket = Socket().apply { connect(InetSocketAddress(address, target.port), budget.timeoutMs()) }
                stream = if (target.transport == "tls") ((SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(socket, target.host, target.port, true) as SSLSocket).apply {
                    sslParameters = sslParameters.apply { if (!target.host.contains(':') && !target.host.first().isDigit()) serverNames = listOf(SNIHostName(target.host)) }
                    startHandshake()
                } else socket
                input = stream!!.getInputStream(); output = stream!!.getOutputStream()
            }
        }
        fun permit(size: Int = 0) {
            if (cancelled()) throw InterruptedException("Stopped")
            budget.check(size)
            if (!allowsLeg(target.scopeUrl, address.hostAddress, target.port)) throw Blocked("Network leg is no longer authorized")
        }
        fun send(data: ByteArray) { permit(data.size); udp?.send(DatagramPacket(data, data.size)) ?: output!!.apply { write(data); flush() } }
        fun receive(): ByteArray {
            udp?.let { socket ->
                socket.soTimeout = budget.timeoutMs()
                val packet = DatagramPacket(ByteArray(65536), 65536); socket.receive(packet)
                budget.bytes -= packet.length
                return packet.data.copyOf(packet.length)
            }
            stream!!.soTimeout = budget.timeoutMs()
            val prefix = exact(4)
            val length = ((prefix[2].toInt() and 0xFF) shl 8) or (prefix[3].toInt() and 0xFF)
            return if (prefix[0].toInt() and 0xC0 == 0x40) prefix + exact(length + (4 - length % 4) % 4) else prefix + exact(16 + length)
        }
        private fun exact(size: Int): ByteArray {
            val out = ByteArray(size); var read = 0
            while (read < size) { val n = input!!.read(out, read, size - read); if (n < 0) throw java.io.EOFException("Peer closed before complete response"); read += n }
            budget.bytes -= size
            return out
        }
        override fun close() { runCatching { udp?.close() }; runCatching { stream?.close() } }
    }

    private inner class Client(val connection: Connection, val username: String, val password: String) {
        var realm = ByteArray(0); var nonce = ByteArray(0); var key: ByteArray? = null; var allocated = false
        var relayed: Pair<InetAddress, Int>? = null
        val evidence = mutableListOf<TestEvidence>()
        fun transaction() = ByteArray(12).also(random::nextBytes)
        fun request(method: Int, attrs: (ByteArray) -> List<Pair<Int, ByteArray>> = { emptyList() }, authenticate: Boolean = true, retry: Boolean = true): Stun.Message {
            val tx = transaction()
            val auth = if (key != null && authenticate) listOf(Stun.USERNAME to username.toByteArray(), Stun.REALM to realm, Stun.NONCE to nonce) else emptyList()
            val packet = Stun.encode(method, tx, attrs(tx) + auth, if (authenticate) key else null)
            connection.send(packet)
            val raw = connection.receive()
            val response = Stun.decode(raw, tx, key)
            evidence += TestEvidence("wire", now(), buildJsonObject { put("hex", packet.hex()) }, buildJsonObject {
                put("hex", raw.hex()); put("type", response.type); response.errorCode()?.let { put("error", it) }
                response.integrity?.let { put("integrity", it) }
            })
            require(response.type == method or 0x100 || response.type == method or 0x110) { "Unexpected STUN response method/class" }
            if (response.errorCode() in setOf(401, 438) && authenticate && username.isNotEmpty() && retry) {
                realm = response.first(Stun.REALM); nonce = response.first(Stun.NONCE)
                require(realm.isNotEmpty() && nonce.isNotEmpty()) { "Challenge lacks realm/nonce" }
                key = MessageDigest.getInstance("MD5").digest(username.toByteArray() + ":".toByteArray() + realm + ":".toByteArray() + password.toByteArray())
                return request(method, attrs, true, false)
            }
            if (method == Stun.ALLOCATE && response.type == 0x103) {
                allocated = true
                relayed = runCatching { Stun.decodeAddress(response.first(Stun.RELAYED), response.transaction) }.getOrNull()
            }
            if (key != null && response.type and 0x110 == 0x100) require(response.integrity == true) { "Authenticated success lacks valid MESSAGE-INTEGRITY" }
            return response
        }
        fun allocate() = request(Stun.ALLOCATE, { listOf(Stun.TRANSPORT to byteArrayOf(17, 0, 0, 0), Stun.LIFETIME to int(60)) })
        fun release(): String {
            if (!allocated) return "not-required"
            val response = request(Stun.REFRESH, { listOf(Stun.LIFETIME to int(0)) })
            allocated = !(response.type == 0x104 && response.first(Stun.LIFETIME).contentEquals(int(0)))
            return if (allocated) "unconfirmed" else "released"
        }
        fun permission(peer: InetAddress, port: Int, channel: Boolean = false): Stun.Message =
            request(if (channel) Stun.CHANNEL_BIND else Stun.PERMISSION, { tx -> listOf(Stun.PEER to Stun.xorAddress(peer, port, tx)) + if (channel) listOf(Stun.CHANNEL to byteArrayOf(0x40, 0, 0, 0)) else emptyList() })
        fun sendTo(peer: InetAddress, port: Int, marker: ByteArray, channel: Boolean) {
            val wire = if (channel) ByteBuffer.allocate(4).putShort(0x4000).putShort(marker.size.toShort()).array() + marker +
                (if (connection.target.transport != "udp") ByteArray((4 - marker.size % 4) % 4) else ByteArray(0))
                else transaction().let { tx -> Stun.encode(Stun.SEND, tx, listOf(Stun.PEER to Stun.xorAddress(peer, port, tx), Stun.DATA_ATTR to marker)) }
            connection.send(wire)
        }
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun int(value: Int) = ByteBuffer.allocate(4).putInt(value).array()

    /** Authorizes a relay destination: the listener's own IP is already authorized; anything else needs scope. */
    private fun allowPeer(target: ProtocolTarget, listener: InetAddress, peer: InetAddress, port: Int): Boolean =
        peer == listener || allowsLeg("https://${if (peer is Inet6Address) "[${peer.hostAddress}]" else peer.hostAddress}:$port/", peer.hostAddress, port)

    private fun echoExternal(client: Client, peerTarget: ProtocolTarget, channel: Boolean): JsonObject {
        val peer = InetAddress.getByName(peerTarget.host)
        if (!allowsLeg(peerTarget.scopeUrl, peer.hostAddress, peerTarget.port)) throw Blocked("Echo peer is outside scope")
        val result = client.permission(peer, peerTarget.port, channel)
        if (result.type != (if (channel) 0x109 else 0x108)) return buildJsonObject { put("permission", false); put("received", false); result.errorCode()?.let { put("error", it) } }
        val marker = ("wrtc-" + java.util.UUID.randomUUID().toString().replace("-", "")).toByteArray()
        client.sendTo(peer, peerTarget.port, marker, channel)
        val raw = client.connection.receive()
        val received = if (channel && raw.size >= 4 && raw[0] == 0x40.toByte() && raw[1] == 0.toByte()) {
            val length = ((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)
            raw.size >= 4 + length && raw.copyOfRange(4, 4 + length).contentEquals(marker)
        } else {
            val message = Stun.decode(raw)
            message.type == Stun.DATA && Stun.decodeAddress(message.first(Stun.PEER), message.transaction) == (peer to peerTarget.port) && message.first(Stun.DATA_ATTR).contentEquals(marker)
        }
        return buildJsonObject { put("permission", true); put("received", received); put("marker", String(marker)); put("responseHex", raw.hex())
            put("peer", buildJsonArray { add(peer.hostAddress); add(peerTarget.port) }); put("path", if (channel) "ChannelData" else "Send/Data") }
    }

    /** Relays a marker from allocation A to allocation B on the same server and checks B receives it. */
    private fun echoSelf(target: ProtocolTarget, sender: Client, receiver: Client, channel: Boolean): JsonObject {
        val (relayB, portB) = receiver.relayed ?: return buildJsonObject { put("received", false); put("error", "Receiver allocation returned no relayed address") }
        val (relayA, portA) = sender.relayed ?: return buildJsonObject { put("received", false); put("error", "Sender allocation returned no relayed address") }
        val listener = sender.connection.address
        if (!allowPeer(target, listener, relayB, portB) || !allowPeer(target, listener, relayA, portA))
            throw Blocked("Relayed addresses differ from the listener IP; add them to Burp scope and the allow-list")
        val toB = sender.permission(relayB, portB, channel)
        val toA = receiver.permission(relayA, portA)
        if (toB.type != (if (channel) 0x109 else 0x108) || toA.type != 0x108)
            return buildJsonObject { put("permission", false); put("received", false); toB.errorCode()?.let { put("error", it) } }
        val marker = ("wrtc-" + java.util.UUID.randomUUID().toString().replace("-", "")).toByteArray()
        sender.sendTo(relayB, portB, marker, channel)
        val raw = receiver.connection.receive()
        val message = runCatching { Stun.decode(raw) }.getOrNull()
        val from = message?.let { runCatching { Stun.decodeAddress(it.first(Stun.PEER), it.transaction) }.getOrNull() }
        val received = message?.type == Stun.DATA && message.first(Stun.DATA_ATTR).contentEquals(marker)
        return buildJsonObject { put("permission", true); put("received", received); put("marker", String(marker)); put("responseHex", raw.hex())
            put("peer", buildJsonArray { add(relayB.hostAddress); add(portB) }); put("from", from?.let { "${it.first.hostAddress}:${it.second}" } ?: "")
            put("path", (if (channel) "ChannelData" else "Send/Data") + " via second allocation") }
    }

    fun run(testId: String, runId: String, engagementId: String, target: ProtocolTarget, timeoutSeconds: Int,
            credentials: List<Credential>, peer: ProtocolTarget?): TestOutcome {
        require(testId in setOf("TRN-01", "TRN-02", "TRN-04", "TRN-05", "TRN-07")) { "Unsupported test ID" }
        require(target.scheme in setOf("stun", "stuns", "turn", "turns")) { "This adapter requires a STUN/TURN listener" }
        require(testId == "TRN-01" || target.scheme in setOf("turn", "turns")) { "Allocation tests require a TURN listener" }
        val budget = Budget(timeoutSeconds)
        val started = now()
        val evidence = mutableListOf<TestEvidence>(); val limitations = mutableListOf<String>(); val cleanup = mutableListOf<String>()
        var execution = "completed"
        val outcomes = mutableListOf<JsonObject>()
        val variants = if (testId == "TRN-02") credentials else credentials.take(1).ifEmpty { listOf(Credential("absent", "", "")) }
        for (identity in variants) {
            val clients = mutableListOf<Client>()
            try {
                val client = Client(Connection(target, budget), identity.username, identity.password).also(clients::add)
                val outcome = if (testId == "TRN-01") {
                    val response = client.request(Stun.BINDING, authenticate = false)
                    buildJsonObject { put("condition", identity.condition); put("binding", response.type == 0x101)
                        put("software", String(response.first(Stun.SOFTWARE))); put("realm", String(response.first(Stun.REALM)))
                        response.errorCode()?.let { put("error", it) }; put("alternateServerHex", response.first(Stun.ALTERNATE).hex()) }
                } else {
                    val response = client.allocate()
                    buildJsonObject {
                        put("condition", identity.condition); put("allocated", client.allocated); response.errorCode()?.let { put("error", it) }
                        put("realm", String(client.realm)); put("nonce", String(client.nonce))
                        client.relayed?.let { put("relayed", "${it.first.hostAddress}:${it.second}") }
                        if (client.allocated && testId in setOf("TRN-04", "TRN-05")) {
                            if (peer != null) {
                                put("transfer", echoExternal(client, peer, false))
                                if (testId == "TRN-05") put("channelTransfer", echoExternal(client, peer, true))
                            } else {
                                val receiver = Client(Connection(target, budget), identity.username, identity.password).also(clients::add)
                                receiver.allocate()
                                if (!receiver.allocated) put("transfer", buildJsonObject { put("received", false); put("error", "Second allocation was refused") })
                                else {
                                    put("transfer", echoSelf(target, client, receiver, false))
                                    if (testId == "TRN-05") put("channelTransfer", echoSelf(target, client, receiver, true))
                                }
                            }
                        }
                        if (client.allocated && testId == "TRN-07") put("refresh", client.request(Stun.REFRESH, { listOf(Stun.LIFETIME to int(60)) }).type == 0x104)
                    }
                }
                outcomes += outcome
                evidence += TestEvidence("case", now(), buildJsonObject { put("condition", identity.condition); put("username", identity.username); put("password", identity.password) }, outcome)
            } catch (e: java.util.concurrent.TimeoutException) { execution = "timeout"; limitations += e.message.orEmpty() }
            catch (e: SocketTimeoutException) { execution = "timeout"; limitations += "No response before the timeout" }
            catch (e: Blocked) { execution = "blocked"; limitations += e.message.orEmpty() }
            catch (e: InterruptedException) { execution = "cancelled"; limitations += "Stopped" }
            catch (e: Exception) { execution = "partial"; limitations += (e.message ?: e.javaClass.simpleName) }
            finally {
                for (client in clients) {
                    cleanup += runCatching { client.release() }.getOrElse { "unconfirmed: ${it.message}" }
                    evidence += client.evidence.takeLast(40)
                    client.connection.close()
                }
            }
            if (execution != "completed") break
        }
        if (cleanup.any { it.startsWith("unconfirmed") }) limitations += "Allocation release unconfirmed; requested lifetime was 60 seconds, server lifetime may differ"
        var control = "not-run"; var security = "observed"
        when (testId) {
            "TRN-01" -> limitations += "Unauthenticated STUN Binding is expected in many deployments. Alternate servers are not followed. RFC 6062 TCP relaying and DTLS listeners are not tested."
            "TRN-02" -> {
                control = if (outcomes.any { it["allocated"]?.jsonPrimitive?.booleanOrNull == true && it["condition"]?.jsonPrimitive?.content == "valid" }) "passed" else "failed"
                security = "inconclusive"
                limitations += "Allocation acceptance is not relay transfer. Expired/revoked conditions require supplied credentials with known lifecycle evidence."
                if (control == "passed" && outcomes.any { it["allocated"]?.jsonPrimitive?.booleanOrNull == true && it["condition"]?.jsonPrimitive?.content in setOf("absent", "incorrect") })
                    limitations += "An allocation succeeded with absent or incorrect credentials: the TURN server may not enforce authentication. Review the case evidence."
            }
            "TRN-04", "TRN-05" -> limitations += if (peer == null) "No echo peer was supplied, so a second allocation on the same server received the marker. This proves relay forwarding works; it does not test which destinations the server refuses (supply a controlled echo peer for that)." else "Delivery to the supplied echo peer only; other destinations need their own runs."
            "TRN-07" -> limitations += "This checks refresh/release only; cross-account ownership, reservations and logout policy require paired scenarios."
        }
        return TestOutcome(engagementId = engagementId, runId = runId, testId = testId, target = target.input, backend = "built-in-turn",
            startedAt = started, endedAt = now(), execution = execution, security = security, confidence = "low", control = control,
            cleanup = cleanup.joinToString("; ").ifEmpty { "not-required" }, evidence = evidence.takeLast(200), limitations = limitations)
    }
}
