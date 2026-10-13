package webrtc.authz

import kotlinx.serialization.json.*
import webrtc.config.IdentityProfile
import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import java.util.Base64
import kotlin.test.*

class SessionAuthorizationTest {
    private fun jwt(sub: String, room: String = "private", exp: Long = Instant.now().epochSecond + 3600): String {
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"$sub\",\"room\":\"$room\",\"exp\":$exp}".toByteArray(UTF_8))
        return "e30.$encoded.signature"
    }
    @Test fun `capture is passive scoped memory only and preserves credentials`() {
        val f = AuthzFixture()
        f.config.save(f.config.config.copy(injectionEnabled = false))
        val req = request(headers = mapOf("Cookie" to "session=raw-secret", "X-CSRF-Token" to " raw csrf "))
        val first = f.catalog.observe(req, "application/json", 200)!!
        f.catalog.observe(req, "application/json", 200)
        assertEquals(1, f.catalog.snapshot().size)
        assertEquals(1, f.catalog.snapshot().single().requests.size)
        assertEquals("session=raw-secret", f.catalog.snapshot().single().identity.headers["Cookie"])
        assertTrue(f.catalog.snapshot().single().details().contains(" raw csrf "))
        assertEquals(0, f.sent.size)
        assertTrue(f.catalog.selection().isEmpty())
        f.catalog.select(first, true); f.catalog.rename(first, "Alice")
        assertEquals("Alice", f.catalog.selection().single().identity.name)
        f.inScope = false
        assertNull(f.catalog.observe(request(headers = mapOf("Authorization" to "Bearer denied"))))
        f.inScope = true
        assertNull(f.catalog.observe(request("https://outside.test/api", headers = mapOf("Cookie" to "session=other"))))
        f.catalog.clear(); assertTrue(f.catalog.selection().isEmpty()); assertTrue(f.catalog.snapshot().isEmpty())
    }
    @Test fun `only JSON reads are offered automatically and storage is bounded`() {
        val f = AuthzFixture()
        val h = mapOf("Authorization" to "Bearer alice")
        f.catalog.observe(request(headers = h), "text/html", 200)
        f.catalog.observe(request("https://app.test/logout", headers = h), "application/json", 200)
        f.catalog.observe(request(method = "POST", headers = h), "application/json", 200)
        f.catalog.observe(request(headers = h), "application/json", 403)
        assertTrue(f.catalog.snapshot().single().requests.isEmpty())
        repeat(8) { f.catalog.observe(request("https://app.test/api/$it", headers = h), "application/json", 200) }
        assertEquals(5, f.catalog.snapshot().single().requests.size)
        val id = f.catalog.snapshot().single().id; f.catalog.select(id, true)
        repeat(101) { f.catalog.observe(request(headers = mapOf("Authorization" to "Bearer session-$it"))) }
        assertEquals(100, f.catalog.snapshot().size); assertTrue(f.catalog.selection().isEmpty())
    }
    @Test fun `matching form and query values remain separate credential bundles`() {
        val f = AuthzFixture()
        f.catalog.observe(request("https://app.test/api?token=same"))
        f.catalog.observe(request(method = "POST", headers = mapOf("Content-Type" to "application/x-www-form-urlencoded"), body = "token=same"))
        assertEquals(2, f.catalog.snapshot().size)
    }
    @Test fun `query tokens are swapped by location with exact encoding and no source leakage`() {
        val alice = request("https://app.test/api/alice?room=alice&jwt=alice&jwt=alice&hint=alice&csrf=owner-csrf",
            headers = mapOf("Authorization" to "Bearer alice", "Cookie" to "sid=alice", "X-CSRF-Token" to "alice-csrf"))
        val bob = IdentityProfile("Bob", headers = mapOf("Cookie" to "sid=bob", "X-CSRF-Token" to "bob-csrf"),
            queryTokens = mapOf("jwt" to "bob+token/="))
        val replay = AuthTokens.apply(alice, bob)
        assertEquals("/api/alice?room=alice&jwt=bob%2Btoken%2F%3D&jwt=bob%2Btoken%2F%3D&hint=alice", replay.path())
        assertNull(replay.headerValue("Authorization")); assertEquals("sid=bob", replay.headerValue("Cookie"))
        assertEquals("bob-csrf", replay.headerValue("X-CSRF-Token"))
        val absent = AuthTokens.apply(alice, null)
        assertEquals("/api/alice?room=alice&hint=alice", absent.path())
        assertNull(absent.headerValue("Cookie")); assertNull(absent.headerValue("X-CSRF-Token"))
    }
    @Test fun `nested JSON and form swaps preserve resource identifiers and literal token values`() {
        val req = request(method = "POST", headers = mapOf("Content-Type" to "application/json"),
            body = "{\"room\":\"alice\",\"auth\":{\"token\":\"alice\",\"csrf\":\"owner-csrf\"},\"a/b\":{\"jwt\":\"one\"}}")
        val profile = AuthTokens.capture(req)
        assertEquals("one", profile.bodyTokens["/a~1b/jwt"])
        val donor = profile.copy(bodyTokens = mapOf("/auth/token" to "bob\"\\$", "/a~1b/jwt" to "two"))
        val replay = Json.parseToJsonElement(AuthTokens.apply(req, donor).bodyToString()).jsonObject
        assertEquals("alice", replay["room"]?.jsonPrimitive?.content)
        assertEquals("bob\"\\$", replay["auth"]?.jsonObject?.get("token")?.jsonPrimitive?.content)
        assertNull(replay["auth"]?.jsonObject?.get("csrf"))
        assertFalse(AuthTokens.apply(req, null).bodyToString().contains("token"))
        val form = request(method = "POST", headers = mapOf("Content-Type" to "application/x-www-form-urlencoded"), body = "room=alice&access_token=alice&csrf=old")
        assertEquals("room=alice&access_token=bob%2B", AuthTokens.apply(form, IdentityProfile("Bob", bodyTokens = mapOf("access_token" to "bob+"))).bodyToString())
        assertFailsWith<IllegalArgumentException> { AuthTokens.apply(req, IdentityProfile("wrong", bodyTokens = mapOf("/other/token" to "secret"))) }
    }
    @Test fun `same origin comparisons remove all credentials and retain baseline evidence`() {
        val f = AuthzFixture()
        val base = request("https://app.test/api/alice?jwt=alice", headers = mapOf("Cookie" to "sid=alice"))
        val bob = IdentityProfile("Bob", queryTokens = mapOf("jwt" to "bob"), origins = listOf("https://app.test/"))
        val outsider = bob.copy(name = "Other origin", origins = listOf("https://other.test/"))
        val results = mutableListOf<AuthzResult>()
        f.runner.run(base, listOf(bob, outsider), "Alice", { true }, onResult = results::add)
        assertEquals(3, f.sent.size)
        assertEquals("/api/alice?jwt=bob", f.sent[1].path()); assertNull(f.sent[1].headerValue("Cookie"))
        assertEquals("/api/alice", f.sent.last().path())
        assertTrue(results.first { it.variant == "identity:Bob" }.flagged)
        assertNotNull(results.first { it.variant == "identity:Bob" }.baselineRequestResponse)
        assertTrue(results.single { it.variant == "SKIPPED" }.note.contains("different origin"))
        assertTrue(results.first { it.variant == "identity:Bob" }.note.contains("Alice → Bob"))
    }
    @Test fun `explicit application token locations are replaced and stripped without touching identifiers`() {
        val f = AuthzFixture()
        val base = request("https://app.test/api?ticket=alice&room=alice", "POST", mapOf("Content-Type" to "application/json"),
            "{\"proof\":\"alice\",\"room\":\"alice\"}")
        val bob = IdentityProfile("Bob", queryTokens = mapOf("ticket" to "bob"), bodyTokens = mapOf("/proof" to "bob"))
        f.runner.run(base, listOf(bob), "Alice", { true }) {}
        assertEquals(3, f.sent.size)
        assertEquals("/api?ticket=bob&room=alice", f.sent[1].path())
        assertEquals("bob", Json.parseToJsonElement(f.sent[1].bodyToString()).jsonObject["proof"]?.jsonPrimitive?.content)
        assertEquals("/api?room=alice", f.sent.last().path())
        val stripped = Json.parseToJsonElement(f.sent.last().bodyToString()).jsonObject
        assertNull(stripped["proof"]); assertEquals("alice", stripped["room"]?.jsonPrimitive?.content)
    }
    @Test fun `HTML shells failed controls and upgrades never become authorization findings`() {
        for (mode in listOf("html", "denied", "no-body")) {
            val f = AuthzFixture()
            when (mode) {
                "html" -> { f.contentType = "text/html"; f.response = { 200 to "<html>public shell</html>" } }
                "denied" -> f.response = { if (f.sent.size == 1) 403 to "denied" else 200 to "{}" }
                "no-body" -> f.response = { 204 to "" }
            }
            val results = mutableListOf<AuthzResult>()
            f.runner.run(request(), listOf(IdentityProfile("Bob")), "Alice", { true }, onResult = results::add)
            assertTrue(results.none { it.flagged }, mode)
        }
        val f = AuthzFixture(); val results = mutableListOf<AuthzResult>()
        f.runner.run(request("https://app.test/http-bind?sid=live&rid=123", "POST"), { true }, results::add)
        f.runner.run(request("https://app.test/xmpp-websocket", headers = mapOf("Upgrade" to "websocket")), { true }, results::add)
        assertEquals(0, f.sent.size); assertTrue(results.all { it.variant == "SKIPPED" })
    }
    @Test fun `scope and stop are checked for the mutated URL before each replay`() {
        for (gate in listOf("scope", "stop", "injection", "allow-list")) {
            val f = AuthzFixture(); var keepGoing = true; val results = mutableListOf<AuthzResult>()
            f.runner.run(request(), listOf(IdentityProfile("Bob")), "Alice", { keepGoing }) { result ->
                results += result
                if (result.variant == "baseline") when (gate) {
                    "scope" -> f.inScope = false
                    "stop" -> keepGoing = false
                    "injection" -> f.config.save(f.config.config.copy(injectionEnabled = false))
                    "allow-list" -> f.config.save(f.config.config.copy(hostAllowList = emptyList()))
                }
            }
            assertEquals(1, f.sent.size, gate); assertEquals("SKIPPED", results.last().variant, gate)
        }
    }
    @Test fun `Jitsi room swaps use donor JWTs in both directions and leave live streams untouched`() {
        val f = AuthzFixture(); val a = jwt("alice", "alpha"); val b = jwt("bob", "beta")
        val ai = f.catalog.observe(request("https://app.test/alpha?jwt=$a"), "text/html", 200)!!
        val bi = f.catalog.observe(request("https://app.test/beta?jwt=$b"), "text/html", 200)!!
        f.catalog.select(ai, true); f.catalog.select(bi, true)
        val text = SessionCatalog.roomSwaps(f.catalog.selection())
        assertTrue(text.contains("https://app.test/alpha?jwt=$b")); assertTrue(text.contains("https://app.test/beta?jwt=$a"))
        assertEquals(0, f.sent.size)
        val expired = jwt("old", exp = 1)
        f.catalog.observe(request("https://app.test/old?jwt=$expired"), "text/html", 200)
        assertEquals("JWT expired (unverified)", f.catalog.snapshot().first().state())
        val handshake = request("https://app.test/tenant/xmpp-websocket?room=alpha&token=$a", headers = mapOf("Upgrade" to "websocket"))
        val id = f.catalog.observe(handshake, source = "WebSocket handshake")!!
        f.catalog.observeXmpp(id, handshake.url(), "<auth mechanism='ANONYMOUS'>full-auth-value</auth>")
        assertTrue(f.catalog.snapshot().first().details().contains("full-auth-value"))
        assertEquals("https://app.test/tenant/alpha?jwt=$a", f.catalog.snapshot().first().roomUrls.single())
        assertEquals(0, f.sent.size)
    }
    @Test fun `identical JWTs across transports are skipped and SASL tokens stay observational`() {
        val f = AuthzFixture(); val token = jwt("alice")
        val results = mutableListOf<AuthzResult>()
        f.runner.run(request("https://app.test/api?jwt=$token"), listOf(IdentityProfile("same token", queryTokens = mapOf("token" to token))),
            "Alice", { true }, onResult = results::add)
        assertEquals(2, f.sent.size)
        assertTrue(results.single { it.variant == "SKIPPED" }.note.contains("no distinct reusable"))
        val auth = Base64.getEncoder().encodeToString(("\u0000alice\u0000" + token).toByteArray(UTF_8))
        f.catalog.observeXmpp(null, "https://app.test/xmpp-websocket", "<auth mechanism='PLAIN'>$auth</auth>", "connection-1")
        val observed = f.catalog.snapshot().single()
        assertFalse(AuthTokens.hasCredentials(observed.identity))
        assertEquals(listOf(token), observed.observedTokens)
        assertTrue(observed.details().contains(auth))
        assertEquals("Fresh protocol login required", observed.state())
    }
}
