package webrtc.datachannel

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*
import webrtc.bridge.ActiveTestController
import webrtc.config.ConfigStore
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap

/**
 * Integrated browser runner. Launches one isolated Chromium per configured session, routed
 * through Burp so the agent is injected, tags every frame with the session name before page
 * scripts run, applies the session's identity, and drives the application's call controls
 * through the DevTools protocol. Start URLs must be allow-listed and in Burp Target scope.
 */
class BrowserRunner(
    private val configStore: ConfigStore,
    private val controller: ActiveTestController,
    private val telemetry: TelemetryTableModel,
    private val api: MontoyaApi? = null
) {
    inner class Live(val session: RunnerSession, val process: Process, val profile: Path, val cdp: CdpClient, val page: String) {
        /** targetId → flattened child session for cross-origin iframes. */
        val children = ConcurrentHashMap<String, String>()
        val startedAt: Long = System.currentTimeMillis()
        val alive: Boolean get() = process.isAlive && !cdp.closed
    }

    private val live = ConcurrentHashMap<String, Live>()
    private val json = Json { ignoreUnknownKeys = true }

    fun sessions(): List<Live> = live.values.filter { it.alive }
    fun live(name: String): Live? = live[name]?.takeIf { it.alive }
    fun isRunning(name: String) = live(name) != null

    // ---- discovery ----

    fun browserCandidates(): List<File> {
        val configured = configStore.config.browserRunner.browserPath
        if (configured.isNotBlank()) return listOf(File(configured))
        val out = mutableListOf<File>()
        val windows = System.getProperty("os.name").orEmpty().startsWith("Windows")
        val mac = System.getProperty("os.name").orEmpty().startsWith("Mac")
        val burpDirs = listOfNotNull(
            runCatching { File(MontoyaApi::class.java.protectionDomain.codeSource.location.toURI()).parentFile }.getOrNull(),
            File(System.getProperty("user.home"), ".BurpSuite"))
        for (dir in burpDirs) {
            File(dir, "burpbrowser").listFiles()?.filter { it.isDirectory }?.sortedByDescending { it.name }?.forEach { version ->
                out += when {
                    windows -> File(version, "chrome.exe")
                    mac -> File(version, "Chromium.app/Contents/MacOS/Chromium")
                    else -> File(version, "chrome")
                }
            }
        }
        if (windows) {
            listOf(System.getenv("ProgramFiles"), System.getenv("ProgramFiles(x86)"), System.getenv("LOCALAPPDATA")).filterNotNull().forEach { base ->
                out += File(base, "Google/Chrome/Application/chrome.exe"); out += File(base, "Microsoft/Edge/Application/msedge.exe"); out += File(base, "Chromium/Application/chrome.exe")
            }
        } else if (mac) {
            out += File("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"); out += File("/Applications/Chromium.app/Contents/MacOS/Chromium")
            out += File("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")
        } else listOf("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium").forEach { out += File(it) }
        return out
    }

    fun browser(): File? = browserCandidates().firstOrNull { it.isFile && it.canExecute() }

    /** The first Burp proxy listener, else 127.0.0.1:8080. */
    fun proxy(): String {
        configStore.config.browserRunner.proxy.takeIf { it.isNotBlank() }?.let { return it }
        val options = listOfNotNull(
            runCatching { api?.burpSuite()?.exportProjectOptionsAsJson("proxy.request_listeners") }.getOrNull(),
            runCatching { api?.burpSuite()?.exportUserOptionsAsJson("proxy.request_listeners") }.getOrNull())
        for (text in options) {
            val port = Regex("\"listener_port\"\\s*:\\s*(\\d+)").find(text)?.groupValues?.get(1) ?: continue
            val mode = Regex("\"listen_mode\"\\s*:\\s*\"([^\"]+)\"").find(text)?.groupValues?.get(1).orEmpty()
            val host = Regex("\"listen_specific_address\"\\s*:\\s*\"([^\"]+)\"").find(text)?.groupValues?.get(1)?.takeIf { mode == "specific_address" } ?: "127.0.0.1"
            return "$host:$port"
        }
        return "127.0.0.1:8080"
    }

    fun vars(session: RunnerSession): Map<String, String> {
        val cfg = configStore.config.browserRunner
        return mapOf("mainRoom" to cfg.mainRoom, "testRoom" to cfg.testRoom, "session" to session.name, "role" to session.role,
            "room" to if (session.room == "test") cfg.testRoom else cfg.mainRoom)
    }

    /** Plain-English problems that would stop a launch. */
    fun check(): List<String> {
        val cfg = configStore.config
        val problems = mutableListOf<String>()
        runCatching { cfg.browserRunner.validate() }.onFailure { problems += it.message.orEmpty() }
        if (browser() == null) problems += "No Chromium-based browser found. Set the browser path (Burp's bundled Chromium, Chrome or Edge)."
        if (!cfg.injectionEnabled) problems += "Enable the browser agent in Setup so runner pages are instrumented."
        if (cfg.browserRunner.sessions.isEmpty()) problems += "Add at least two sessions (for example a customer and an advisor)."
        cfg.browserRunner.sessions.forEach { s ->
            val url = CallControls.substitute(s.url, vars(s))
            if (url.isBlank() && CallControls.parse(s.join).none { it.action == "navigate" }) problems += "Session '${s.name}' needs a start URL or a navigate step in Join."
            else if (url.isNotBlank() && !controller.pageAllowed(url)) problems += "Session '${s.name}': $url is not allow-listed and in Burp Target scope."
        }
        if (cfg.browserRunner.sessions.none { it.room == "test" }) problems += "Optional: add a session in the test room so cross-room isolation can be observed."
        return problems
    }

    // ---- lifecycle ----

    @Synchronized fun launch(session: RunnerSession): Live {
        live(session.name)?.let { return it }
        val cfg = configStore.config.browserRunner
        val url = CallControls.substitute(session.url, vars(session))
        require(url.isBlank() || controller.pageAllowed(url)) { "Start URL must be allow-listed and in Burp Target scope: $url" }
        val exe = browser() ?: throw IllegalStateException("No Chromium-based browser found; set the browser path")
        val profile = if (cfg.keepProfiles) Path.of(System.getProperty("user.home"), ".webrtc-testsuite", "profiles", session.name.replace(Regex("[^A-Za-z0-9_.-]"), "_"))
            else Files.createTempDirectory("webrtc-runner-")
        Files.createDirectories(profile)
        val portFile = profile.resolve("DevToolsActivePort").toFile()
        portFile.delete()
        val args = mutableListOf(exe.absolutePath, "--user-data-dir=$profile", "--remote-debugging-port=0", "--proxy-server=http://${proxy()}",
            // A fresh profile does not trust Burp's CA; this browser is only used for the controlled sessions.
            "--ignore-certificate-errors", "--no-first-run", "--no-default-browser-check", "--disable-default-apps",
            "--disable-background-networking", "--disable-component-update",
            "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", "--autoplay-policy=no-user-gesture-required",
            // Several call windows run at once; background throttling would slow the agents' polls and timers.
            "--disable-background-timer-throttling", "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows",
            "--window-size=1100,800")
        if (cfg.headless) args += "--headless=new"
        args += "about:blank"
        val process = ProcessBuilder(args).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            val deadline = System.currentTimeMillis() + 20000
            while (!(portFile.isFile && portFile.readLines().size >= 2)) {
                check(process.isAlive) { "The browser exited during startup (exit code ${runCatching { process.exitValue() }.getOrNull()}). Close other windows using this profile." }
                check(System.currentTimeMillis() < deadline) { "The browser did not open a DevTools port within 20 s" }
                Thread.sleep(150)
            }
            val (port, path) = portFile.readLines().let { it[0].trim() to it[1].trim() }
            val cdp = CdpClient.connect("ws://127.0.0.1:$port$path")
            val targets = cdp.call("Target.getTargets")["targetInfos"] as? JsonArray
            val targetId = targets?.mapNotNull { it as? JsonObject }?.firstOrNull { it.str("type") == "page" }?.str("targetId")
                ?: cdp.call("Target.createTarget", buildJsonObject { put("url", "about:blank") }).str("targetId")!!
            val page = cdp.call("Target.attachToTarget", buildJsonObject { put("targetId", targetId); put("flatten", true) }).str("sessionId")!!
            val result = Live(session, process, profile, cdp, page)
            val tag = "window.__WRTC_RUNNER_SESSION__ = ${JsonPrimitive(session.name)};"
            cdp.onEvent { method, _, params ->
                if (method != "Target.attachedToTarget") return@onEvent
                val child = params.str("sessionId") ?: return@onEvent
                val info = params["targetInfo"] as? JsonObject
                runCatching {
                    if (info?.str("type") in setOf("iframe", "page")) {
                        info?.str("targetId")?.let { result.children[it] = child }
                        cdp.call("Page.addScriptToEvaluateOnNewDocument", buildJsonObject { put("source", tag) }, child)
                        cdp.call("Target.setAutoAttach", buildJsonObject { put("autoAttach", true); put("waitForDebuggerOnStart", true); put("flatten", true) }, child)
                        identityHeaders(session)?.let { cdp.call("Network.enable", sessionId = child); cdp.call("Network.setExtraHTTPHeaders", buildJsonObject { put("headers", it) }, child) }
                    }
                }
                runCatching { cdp.call("Runtime.runIfWaitingForDebugger", sessionId = child) }
            }
            cdp.call("Page.enable", sessionId = page)
            cdp.call("Network.enable", sessionId = page)
            cdp.call("Page.addScriptToEvaluateOnNewDocument", buildJsonObject { put("source", tag) }, page)
            cdp.call("Target.setAutoAttach", buildJsonObject { put("autoAttach", true); put("waitForDebuggerOnStart", true); put("flatten", true) }, page)
            applyIdentity(result, url)
            live[session.name] = result
            log(session.name, "launched", "Launched ${exe.name} for session '${session.name}' (${session.role}, room ${session.room}) via proxy ${proxy()}")
            if (url.isNotBlank()) cdp.call("Page.navigate", buildJsonObject { put("url", url) }, page)
            return result
        } catch (t: Throwable) {
            process.destroyForcibly()
            throw t
        }
    }

    private fun identity(session: RunnerSession) = configStore.config.identities.firstOrNull { it.name == session.identity && session.identity.isNotBlank() }

    private fun identityHeaders(session: RunnerSession): JsonObject? = identity(session)?.headers?.filterKeys { !it.equals("cookie", true) && !it.equals("host", true) }
        ?.takeIf { it.isNotEmpty() }?.let { headers -> buildJsonObject { headers.forEach { (k, v) -> put(k, v) } } }

    /** Identity cookies become browser cookies for the start URL; other headers are sent with every request. */
    private fun applyIdentity(live: Live, url: String) {
        val profile = identity(live.session) ?: return
        identityHeaders(live.session)?.let { live.cdp.call("Network.setExtraHTTPHeaders", buildJsonObject { put("headers", it) }, live.page) }
        val cookie = profile.headers.entries.firstOrNull { it.key.equals("cookie", true) }?.value ?: return
        if (url.isBlank()) return
        val cookies = buildJsonArray {
            cookie.split(';').map { it.trim() }.filter { it.contains('=') }.forEach { pair ->
                add(buildJsonObject { put("name", pair.substringBefore('=')); put("value", pair.substringAfter('=')); put("url", url) })
            }
        }
        live.cdp.call("Network.setCookies", buildJsonObject { put("cookies", cookies) }, live.page)
    }

    fun close(name: String) {
        val session = live.remove(name) ?: return
        runCatching { session.cdp.call("Browser.close", timeoutMs = 3000) }
        runCatching { session.cdp.close() }
        if (!session.process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) session.process.destroyForcibly()
        if (!configStore.config.browserRunner.keepProfiles) runCatching { session.profile.toFile().deleteRecursively() }
        log(name, "closed", "Closed runner session '$name'")
    }

    fun closeAll() = live.keys.toList().forEach(::close)

    // ---- driving ----

    /** Evaluate JavaScript in the session's top frame, or in the frame whose URL contains [frame]. */
    fun evaluate(name: String, expression: String, frame: String = "", timeoutMs: Long = 15000): JsonElement? {
        val session = live(name) ?: throw IllegalStateException("Session '$name' is not running")
        var target = session.page
        var code = expression
        if (frame.isNotBlank()) {
            val infos = (session.cdp.call("Target.getTargets")["targetInfos"] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
            val child = infos.firstOrNull { it.str("url")?.contains(frame) == true && session.children.containsKey(it.str("targetId")) }
            if (child != null) target = session.children.getValue(child.str("targetId")!!)
            else code = "(function(){function find(w){try{if(w.location.href.indexOf(${JsonPrimitive(frame)})>=0)return w;}catch(e){}" +
                "for(var i=0;i<w.frames.length;i++){var r=find(w.frames[i]);if(r)return r;}return null;}" +
                "var w=find(window);if(!w)throw new Error('Frame not found: '+${JsonPrimitive(frame)});return w.eval(${JsonPrimitive(expression)});})()"
        }
        val result = session.cdp.call("Runtime.evaluate", buildJsonObject {
            put("expression", code); put("awaitPromise", true); put("returnByValue", true); put("userGesture", true)
        }, target, timeoutMs)
        (result["exceptionDetails"] as? JsonObject)?.let { details ->
            val description = ((details["exception"] as? JsonObject)?.str("description") ?: details.str("text")).orEmpty()
            throw IllegalStateException(description.lineSequence().firstOrNull().orEmpty().ifBlank { "Script error" })
        }
        return (result["result"] as? JsonObject)?.get("value")
    }

    fun setOffline(name: String, offline: Boolean) {
        val session = live(name) ?: return
        val conditions = buildJsonObject { put("offline", offline); put("latency", 0); put("downloadThroughput", -1); put("uploadThroughput", -1) }
        (listOf(session.page) + session.children.values).forEach { runCatching { session.cdp.call("Network.emulateNetworkConditions", conditions, it) } }
    }

    /** The session's agent: the frame with an open runner transport, else its most recent page. */
    fun agentFor(name: String): ActiveTestController.Agent? {
        val tagged = controller.agents().filter { (it.state["runnerSession"] as? JsonPrimitive)?.contentOrNull == name }
        return tagged.firstOrNull { hasTransport(it) } ?: tagged.maxByOrNull { it.seen }
    }

    fun agentsFor(name: String): List<ActiveTestController.Agent> =
        controller.agents().filter { (it.state["runnerSession"] as? JsonPrimitive)?.contentOrNull == name }

    fun hasTransport(agent: ActiveTestController.Agent): Boolean =
        agent.channels.any { it.state == "open" } || (agent.state["sockets"] as? JsonArray).orEmpty().any { (it as? JsonObject)?.str("state") == "open" }

    fun endpointFor(name: String): String {
        val session = live(name)?.session ?: return ""
        if (session.endpointExpr.isBlank()) return ""
        return runCatching { (evaluate(name, session.endpointExpr) as? JsonPrimitive)?.contentOrNull.orEmpty() }.getOrDefault("")
    }

    /** Run one of the session's call-control scripts ("join", "leave", "hangup", "remove") or a literal script. */
    fun runSteps(name: String, which: String, cancelled: () -> Boolean = { false }, literal: String? = null) {
        val session = live(name)?.session ?: throw IllegalStateException("Session '$name' is not running")
        val script = literal ?: when (which) { "join" -> session.join; "leave" -> session.leave; "hangup" -> session.hangup; "remove" -> session.remove; else -> "" }
        val steps = CallControls.parse(CallControls.substitute(script, vars(session)))
        log(name, which, "Session '$name': running $which (${steps.size} step(s))")
        for (step in steps) {
            check(!cancelled()) { "Stopped" }
            runCatching { perform(name, step, cancelled) }.onFailure {
                log(name, "$which-error", "Session '$name' $which failed at '${step.line.trim()}': ${it.message}")
                throw IllegalStateException("$which step '${step.line.trim()}' failed: ${it.message}")
            }
        }
    }

    private fun perform(name: String, step: CallControls.Step, cancelled: () -> Boolean) {
        val session = live(name) ?: throw IllegalStateException("Session '$name' is not running")
        fun poll(timeout: Long, condition: () -> Boolean) {
            val deadline = System.currentTimeMillis() + timeout
            while (!condition()) {
                check(!cancelled()) { "Stopped" }
                check(System.currentTimeMillis() < deadline) { "Timed out after $timeout ms" }
                Thread.sleep(250)
            }
        }
        when (step.action) {
            "navigate" -> {
                require(controller.pageAllowed(step.argument)) { "${step.argument} is not allow-listed and in Burp Target scope" }
                session.cdp.call("Page.navigate", buildJsonObject { put("url", step.argument) }, session.page)
            }
            "reload" -> session.cdp.call("Page.reload", sessionId = session.page)
            "sleep" -> Thread.sleep(step.timeoutMs)
            "offline" -> { setOffline(name, true); try { Thread.sleep(step.timeoutMs) } finally { setOffline(name, false) } }
            "waitchannel" -> poll(step.timeoutMs) { agentFor(name)?.let(::hasTransport) == true }
            "wait", "waitjs" -> poll(step.timeoutMs) { runCatching { (evaluate(name, CallControls.script(step)!!, step.frame) as? JsonPrimitive)?.booleanOrNull == true }.getOrDefault(false) }
            else -> evaluate(name, CallControls.script(step)!!, step.frame)
        }
    }

    private fun log(session: String, action: String, detail: String) {
        val raw = buildJsonObject { put("type", "runner-action"); put("session", session); put("action", action); put("detail", detail) }
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")), "runner-action", "runner:$session", "", false, detail, raw.toString()))
    }

    private fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.contentOrNull
}
