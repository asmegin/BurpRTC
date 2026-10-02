package webrtc.tls

import burp.api.montoya.MontoyaApi
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryTableModel
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.Path
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.*

class TlsScanRunnerTest {
    @Test fun `real Python setup runtime check and closed local listener scan`() {
        val executable = System.getenv("WEBRTC_TLS_SMOKE_PYTHON")
        org.junit.Assume.assumeTrue("Optional real Python integration: set WEBRTC_TLS_SMOKE_PYTHON", !executable.isNullOrBlank())
        val store = store().also { it.save(it.config.copy(hostAllowList = listOf("localhost"))) }
        val port = ServerSocket(0).use { it.localPort }
        val cfg = TlsScanConfig(pythonExecutable = executable!!, endpoint = "turns:localhost:$port?transport=tcp", timeoutSeconds = 30)
        val telemetry = TelemetryTableModel()
        val runner = TlsScanRunner(store, { it == "https://localhost:$port/" }, telemetry, Files.createTempDirectory("tls-real"))
        runner.use {
            assertEquals("ready", it.setup(cfg).status)
            assertEquals("ready", it.check(cfg).status)
            val outcome = it.scan(cfg)
            assertEquals("failed", outcome.status)
            assertNotNull(outcome.result?.get("raw")) // Captured actual SSLyze connectivity failure, not a fabricated pass.
            assertEquals("tls-scan-result", telemetry.snapshot().last().type)
        }
    }
    private fun store(): ConfigStore {
        var persisted: String? = null
        fun proxy(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            when {
                method.name == "getString" -> persisted
                method.name == "setString" -> { persisted = args!![1] as String; null }
                method.returnType.isInterface -> proxy(method.returnType)
                else -> null
            }
        }
        return ConfigStore(proxy(MontoyaApi::class.java) as MontoyaApi).also {
            it.save(it.config.copy(injectionEnabled = true, hostAllowList = listOf("example.test")))
        }
    }
    private val config = TlsScanConfig(endpoint = "turns:example.test:5349?transport=tcp")
    private val output = """{"schema":1,"engine":"SSLyze 6.3.1","hostname":"example.test","port":5349,"status":"partial","checks":[{"name":"heartbleed","status":"error","summary":"timeout"}],"findings":[],"raw":{}}"""

    private class FakeProcess(output: String = "", private val onWait: () -> Boolean = { true }) : Process() {
        val stdin = ByteArrayOutputStream()
        @Volatile var alive = true
        @Volatile var killed = false
        private val stdout = ByteArrayInputStream(output.toByteArray())
        override fun getInputStream() = stdout
        override fun getErrorStream() = ByteArrayInputStream(ByteArray(0))
        override fun getOutputStream() = stdin
        override fun waitFor(): Int { alive = false; return 0 }
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = (!alive || onWait()).also { if (it) alive = false }
        override fun exitValue() = if (alive) throw IllegalThreadStateException() else 0
        override fun isAlive() = alive
        override fun destroy() { alive = false; killed = true }
        override fun destroyForcibly(): Process { destroy(); return this }
    }

    private fun prepare(runner: TlsScanRunner, cfg: TlsScanConfig = config) {
        val python = runner.runtimeDirectory(cfg).resolve(if (System.getProperty("os.name").startsWith("Windows")) "Scripts/python.exe" else "bin/python")
        Files.createDirectories(python.parent); Files.writeString(python, "test executable")
    }

    @Test fun `secure listener parsing preserves scope path port query and ipv6`() {
        assertEquals("https://example.test:8443/call?token=abc", TlsTarget.parse("wss://example.test:8443/call?token=abc").scopeUrl)
        assertEquals("https://example.test/call", TlsTarget.parse("https://example.test/call").scopeUrl)
        assertEquals(443, TlsTarget.parse("wss://example.test/call").port)
        assertEquals(TlsTarget("turns:[::1]:5349", "::1", 5349, "https://[::1]:5349/"), TlsTarget.parse("turns:[::1]:5349"))
        assertEquals(5349, TlsTarget.parse("turns:example.test").port)
        assertEquals("https://example.test:4443/", TlsTarget.parse("tls://example.test:4443").scopeUrl)
    }

    @Test fun `non TLS candidate ambiguous authority and DTLS endpoints are rejected`() {
        for (target in listOf("http://example.test", "turn:example.test", "stuns:example.test", "turns:example.test?transport=udp",
            "tls://example.test", "tls://example.test:443/path", "tls://example.test:443?extra=x", "https://user@example.test/", "https://example.test/#fragment", "https://example.test:70000", "192.168.1.5:443"))
            assertFailsWith<IllegalArgumentException>(target) { TlsTarget.parse(target) }
    }

    @Test fun `config persists with disabled run all by default`() {
        val store = store()
        assertFalse(store.config.tlsScan.includeInRunAll)
        store.save(store.config.copy(tlsScan = config.copy(pythonExecutable = "C:/Python folder/python.exe", includeInRunAll = true)))
        assertEquals(store.config.tlsScan, store.load().tlsScan)
    }

    @Test fun `scope injection and allow list block before any process starts`() {
        val store = store()
        var scoped = false
        var starts = 0
        val runner = TlsScanRunner(store, { scoped }, TelemetryTableModel(), Files.createTempDirectory("tls-scope"), { starts++; FakeProcess(output) })
        prepare(runner)
        assertEquals("blocked", runner.scan(config).status)
        scoped = true
        store.save(store.config.copy(injectionEnabled = false))
        assertEquals("blocked", runner.scan(config).status)
        store.save(store.config.copy(injectionEnabled = true, hostAllowList = listOf("other.test")))
        assertEquals("blocked", runner.scan(config).status)
        assertEquals(0, starts)
    }

    @Test fun `script execution uses one argument per path and structured stdin with partial result preserved`() {
        val telemetry = TelemetryTableModel()
        val process = FakeProcess(output)
        var command = emptyList<String>()
        var scopedUrl = ""
        val runner = TlsScanRunner(store(), { scopedUrl = it; true }, telemetry, Files.createTempDirectory("tls folder"), { command = it; process })
        prepare(runner)
        assertEquals("partial", runner.scan(config).status)
        assertEquals("https://example.test:5349/", scopedUrl)
        assertEquals(4, command.size)
        assertEquals(listOf("-I", "-u"), command.subList(1, 3))
        assertTrue(command[3].endsWith("tls_runner-1.0.3.py"))
        assertEquals("""{"hostname":"example.test","port":5349,"vulnerabilityChecks":false}""", process.stdin.toString(Charsets.UTF_8))
        assertEquals(listOf("tls-scan-start", "tls-scan-result"), telemetry.snapshot().map { it.type })
        assertTrue(telemetry.snapshot().last().raw.contains("heartbleed"))
    }

    @Test fun `scope removal terminates running process and reports blocked`() {
        var allowed = true
        val process = FakeProcess(onWait = { allowed = false; false })
        val runner = TlsScanRunner(store(), { allowed }, TelemetryTableModel(), Files.createTempDirectory("tls-revoke"), { process })
        prepare(runner)
        assertEquals("blocked", runner.scan(config).status)
        assertTrue(process.killed)
        assertFalse(runner.isBusy())
    }

    @Test fun `stop prevents concurrent jobs and unload prevents future jobs`() {
        val entered = CountDownLatch(1)
        val process = FakeProcess(onWait = { entered.countDown(); Thread.sleep(10); false })
        val runner = TlsScanRunner(store(), { true }, TelemetryTableModel(), Files.createTempDirectory("tls-stop"), { process })
        prepare(runner)
        var outcome: TlsScanRunner.Outcome? = null
        val worker = Thread { outcome = runner.scan(config) }.apply { start() }
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        assertEquals("busy", runner.scan(config).status)
        runner.stop(); worker.join(2000)
        assertFalse(worker.isAlive)
        assertEquals("cancelled", outcome?.status)
        assertTrue(process.killed)
        runner.close()
        assertEquals("failed", runner.scan(config).status)
    }

    @Test fun `time budget kills subprocess and malformed evidence is failed`() {
        val ticks = AtomicLong(0)
        val process = FakeProcess(onWait = { false })
        val runner = TlsScanRunner(store(), { true }, TelemetryTableModel(), Files.createTempDirectory("tls-timeout"), { process },
            { ticks.addAndGet(TimeUnit.SECONDS.toNanos(5)) })
        prepare(runner)
        assertEquals("timeout", runner.scan(config.copy(timeoutSeconds = 15)).status)
        assertTrue(process.killed)
        val bad = TlsScanRunner(store(), { true }, TelemetryTableModel(), Files.createTempDirectory("tls-bad"), { FakeProcess("{}") })
        prepare(bad)
        assertEquals("failed", bad.scan(config).status)
    }

    @Test fun `setup creates managed environment installs pinned tool and checks native imports`() {
        val commands = mutableListOf<List<String>>()
        val runner = TlsScanRunner(store(), { false }, TelemetryTableModel(), Files.createTempDirectory("tls-setup"), {
            commands.add(it)
            FakeProcess(if (it.last() == "--check") """{"ready":true,"engine":"SSLyze 6.3.1","python":"3.13.1"}""" else "")
        })
        assertEquals("ready", runner.setup(config.copy(pythonExecutable = "C:/Python folder/python.exe")).status)
        assertEquals(4, commands.size)
        assertEquals("C:/Python folder/python.exe", commands.first().first())
        assertTrue(commands[1].contains("venv"))
        assertTrue(commands[2].contains("sslyze==6.3.1"))
        assertTrue(commands.last().last() == "--check")
    }
}
