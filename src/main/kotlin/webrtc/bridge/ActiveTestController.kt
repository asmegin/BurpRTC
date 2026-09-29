package webrtc.bridge

import kotlinx.serialization.json.*
import webrtc.config.*
import webrtc.scope.ScopeGate
import webrtc.telemetry.TelemetryEvent
import webrtc.telemetry.TelemetryTableModel
import java.net.URI
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.UUID

/** In-memory, page-specific jobs. No active operation is restored from the project. */
class ActiveTestController(
    private val config: ConfigStore,
    private val inScope: (String) -> Boolean,
    private val telemetry: TelemetryTableModel,
    private val now: () -> Long = System::currentTimeMillis
) {
    data class Channel(val id: String, val pc: String, val label: String, val state: String)
    data class Agent(val id: String, val frame: String, val seen: Long, val channels: List<Channel>, val iceUrls: List<String> = emptyList(), val version: String = "") {
        override fun toString() = "${id.takeLast(8)} | $frame"
    }
    private data class Job(
        val id: String, val agent: String, val frame: String, val type: String,
        val payload: JsonObject, val endpoint: String?, val expires: Long, var state: String = "queued"
    )
    private val agents = LinkedHashMap<String, Agent>()
    private val jobs = LinkedHashMap<String, Job>()
    private val json = Json { encodeDefaults = true }
    private val activeStates = setOf("queued", "running")

    fun pageAllowed(frame: String): Boolean {
        val cfg = config.config
        val uri = runCatching { URI(frame) }.getOrNull() ?: return false
        return cfg.injectionEnabled && uri.scheme in listOf("http", "https") && uri.host != null &&
            uri.userInfo == null && ScopeGate.hostAllowed(uri.host, cfg.hostAllowList) && inScope(frame)
    }

    @Synchronized fun observe(obj: JsonObject) {
        val id = obj.str("agent")
        if (id.isEmpty() || id.length > 128) return
        if (obj.str("type") == "agent-state") {
            val frame = obj.str("frame")
            val channels = (obj["channels"] as? JsonArray).orEmpty().take(128).mapNotNull { value ->
                val c = value as? JsonObject ?: return@mapNotNull null
                Channel(c.str("channelId"), c.str("pc"), c.str("label"), c.str("state"))
            }
            val iceUrls = (obj["iceServers"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.take(32)
            agents[id] = Agent(id, frame, now(), channels, iceUrls, obj.str("version"))
            while (agents.size > 256) agents.remove(agents.keys.first())
            (obj["completed"] as? JsonArray).orEmpty().take(32).forEach { value ->
                val result = value as? JsonObject ?: return@forEach
                complete(id, frame, result)
            }
        }
        if (obj.str("type") == "command-result") {
            complete(id, obj.str("frame"), obj)
        }
    }

    private fun complete(agent: String, frame: String, result: JsonObject) {
        val job = jobs[result.str("commandId")] ?: return
        if (job.agent == agent && job.frame == frame && job.state in activeStates) {
            transition(job, result.str("status").takeIf { it in setOf("completed", "failed", "cancelled") } ?: "failed")
        }
    }

    @Synchronized fun agents(): List<Agent> = agents.values.filter { now() - it.seen < 15000 }

    @Synchronized fun queueFuzz(agentId: String, channelId: String, settings: DataChannelFuzzConfig): String {
        settings.validate()
        val agent = freshAgent(agentId)
        require(agent.channels.any { it.id == channelId && it.state == "open" }) { "Select an open DataChannel; refresh the page/channel list" }
        return enqueue(agent, "dc-fuzz", buildJsonObject {
            put("channelId", channelId)
            put("config", json.encodeToJsonElement(DataChannelFuzzConfig.serializer(), settings))
        }, null)
    }

    @Synchronized fun queueIce(agentId: String, settings: IceProbeConfig): String {
        val endpoint = settings.validate()
        require(endpoint == null || inScope(endpoint.scopeUrl)) { "Add the ICE endpoint to Burp Target scope: ${endpoint?.scopeUrl}" }
        return enqueue(freshAgent(agentId), "ice-probe", buildJsonObject {
            put("config", json.encodeToJsonElement(IceProbeConfig.serializer(), settings))
        }, endpoint?.scopeUrl)
    }

    @Synchronized fun queueSdpFuzz(agentId: String, settings: SdpFuzzConfig): String {
        settings.validate()
        return enqueue(freshAgent(agentId), "sdp-fuzz", buildJsonObject {
            put("config", json.encodeToJsonElement(SdpFuzzConfig.serializer(), settings))
        }, null)
    }

    @Synchronized fun queueBrowserChecks(agentId: String): String = enqueue(freshAgent(agentId), "browser-checks", buildJsonObject {}, null)

    /** T1 — force a fresh getStats() snapshot from every live peer on the page. */
    @Synchronized fun queueCaptureStats(agentId: String): String =
        enqueue(freshAgent(agentId), "capture-stats", buildJsonObject {}, null)

    /** T8 — bounded, opt-in local renegotiation/ICE-restart loop. Nothing is sent to the signaling server. */
    @Synchronized fun queueSignalingFlood(agentId: String, settings: SignalingFloodConfig): String {
        settings.validate()
        return enqueue(freshAgent(agentId), "signaling-flood", buildJsonObject {
            put("config", json.encodeToJsonElement(SignalingFloodConfig.serializer(), settings))
        }, null)
    }

    @Synchronized fun jobState(id: String): String? { expire(); return jobs[id]?.state }

    fun endpointAllowed(url: String): Boolean = runCatching { inScope(IceEndpoint.parse(url).scopeUrl) }.getOrDefault(false)

    private fun freshAgent(id: String): Agent {
        val agent = agents[id] ?: throw IllegalArgumentException("Select a live browser page; reload it if needed")
        require(now() - agent.seen < 15000) { "Browser page is no longer responding" }
        require(pageAllowed(agent.frame)) { "The page must be allow-listed, in Burp scope, and injection enabled" }
        return agent
    }

    private fun enqueue(agent: Agent, type: String, payload: JsonObject, endpoint: String?): String {
        expire()
        require(jobs.values.none { it.agent == agent.id && it.state in activeStates }) { "This page already has an active test; stop it before starting another" }
        require(jobs.values.count { it.state in activeStates } < 32) { "Too many active tests" }
        val job = Job(UUID.randomUUID().toString(), agent.id, agent.frame, type, payload, endpoint, now() + 90000)
        jobs[job.id] = job
        while (jobs.size > 256) jobs.values.firstOrNull { it.state !in activeStates }?.let { jobs.remove(it.id) } ?: break
        record(job, "queued")
        return job.id
    }

    @Synchronized fun commands(agentId: String, frame: String): List<JsonObject> {
        expire()
        return jobs.values.filter { it.agent == agentId && it.frame == frame && it.state == "queued" }.mapNotNull { job ->
            if (!allowed(job, frame)) { transition(job, "cancelled"); null }
            else buildJsonObject {
                put("id", job.id); put("type", job.type)
                put("agent", job.agent); put("frame", job.frame)
                job.payload.forEach { (key, value) -> put(key, value) }
            }
        }
    }

    @Synchronized fun authorize(agentId: String, frame: String, commandId: String): Boolean {
        expire()
        val job = jobs[commandId] ?: return false
        if (job.agent != agentId || job.frame != frame || job.state !in activeStates) return false
        if (!allowed(job, frame)) { transition(job, "cancelled"); return false }
        if (job.state == "queued") transition(job, "running")
        return true
    }

    private fun allowed(job: Job, frame: String) = pageAllowed(frame) && (job.endpoint == null || inScope(job.endpoint))

    @Synchronized fun cancel(agentId: String, type: String) {
        jobs.values.filter { it.agent == agentId && it.type == type && it.state in activeStates }.forEach { transition(it, "cancelled") }
    }

    @Synchronized fun cancelJob(commandId: String): Boolean {
        val job = jobs[commandId] ?: return false
        if (job.state !in activeStates) return false
        transition(job, "cancelled")
        return true
    }

    @Synchronized fun cancelAll() {
        jobs.values.filter { it.state in activeStates }.forEach { transition(it, "cancelled") }
    }

    private fun expire() {
        jobs.values.filter { it.state in activeStates && it.expires <= now() }.forEach { transition(it, "expired") }
    }

    private fun transition(job: Job, state: String) { job.state = state; record(job, state) }

    private fun record(job: Job, state: String) {
        val detail = "${job.type} ${job.id.take(8)} $state"
        val raw = buildJsonObject {
            put("type", "test-job"); put("commandId", job.id); put("module", job.type)
            put("agent", job.agent); put("frame", job.frame); put("status", state); put("detail", detail)
        }
        telemetry.add(TelemetryEvent(telemetry.nextSeq(), LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS")),
            "test-job", job.frame, "", false, detail, raw.toString()))
    }

    private fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.contentOrNull.orEmpty()
}
