package webrtc.tls

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.net.ServerSocket
import kotlin.test.*

class JvmTlsScannerTest {
    @Test fun `client hello carries the offered version, suites and server name`() {
        val hello = JvmTlsScanner.clientHello("turn.bank.test", 0x0303, listOf(0xC02F, 0x000A))
        assertEquals(0x16, hello[0].toInt())
        assertEquals(1, hello[5].toInt())
        assertEquals(0x03, hello[9].toInt()); assertEquals(0x03, hello[10].toInt())
        assertTrue(String(hello, Charsets.ISO_8859_1).contains("turn.bank.test"))
        assertEquals(hello.size - 5, ((hello[3].toInt() and 0xFF) shl 8) or (hello[4].toInt() and 0xFF))
        assertFalse(String(JvmTlsScanner.clientHello("192.0.2.1", 0x0300, listOf(0x000A)), Charsets.ISO_8859_1).contains("192.0.2.1"))
    }

    @Test fun `server hello version and cipher are parsed and alerts are rejected`() {
        val body = byteArrayOf(0x03, 0x03) + ByteArray(32) + byteArrayOf(0) + byteArrayOf(0xC0.toByte(), 0x2F) + byteArrayOf(0)
        val handshake = byteArrayOf(2, 0, 0, body.size.toByte()) + body
        val record = byteArrayOf(0x16, 3, 3, 0, handshake.size.toByte()) + handshake
        assertEquals(0x0303 to 0xC02F, JvmTlsScanner.parseServerHello(DataInputStream(ByteArrayInputStream(record))))
        val alert = byteArrayOf(0x15, 3, 3, 0, 2, 2, 40)
        assertNull(JvmTlsScanner.parseServerHello(DataInputStream(ByteArrayInputStream(alert))))
    }

    @Test fun `a listener that does not speak TLS is reported without crashing and scope loss stops the scan`() {
        ServerSocket(0).use { server ->
            val acceptor = Thread { runCatching { while (true) server.accept().close() } }.apply { isDaemon = true; start() }
            val result = JvmTlsScanner({ true }, { false }, System.nanoTime() + 20_000_000_000L, 2000).scan("127.0.0.1", server.localPort)
            assertEquals("completed", result["status"].toString().trim('"'))
            assertTrue(result.toString().contains("No TLS handshake succeeded"))
            val blocked = JvmTlsScanner({ false }, { false }, System.nanoTime() + 20_000_000_000L, 2000).scan("127.0.0.1", server.localPort)
            assertEquals("failed", blocked["status"].toString().trim('"'))
            assertTrue(blocked.toString().contains("scope"))
            acceptor.interrupt()
        }
    }
}
