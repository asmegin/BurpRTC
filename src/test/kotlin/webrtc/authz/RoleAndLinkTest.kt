package webrtc.authz

import webrtc.config.IdentityProfile
import java.util.Base64
import kotlin.test.*

class RoleAndLinkTest {
    private fun jwt(sub: String) = listOf("""{"alg":"HS256"}""", """{"sub":"$sub","email":"$sub@bank.test"}""", "sig")
        .joinToString(".") { Base64.getUrlEncoder().withoutPadding().encodeToString(it.toByteArray()) }

    @Test fun `a customer receiving advisor-only data is a likely violation when the control is denied`() {
        val f = AuthzFixture()
        f.response = { req -> if (req.headerValue("Cookie") == null) 401 to "denied" else 200 to "{\"customers\":[\"c1\",\"c2\"]}" }
        val advisor = IdentityProfile("Advisor", headers = mapOf("Cookie" to "sid=advisor"), role = "advisor")
        val customer = IdentityProfile("Customer", headers = mapOf("Cookie" to "sid=customer"), role = "customer")
        val results = mutableListOf<AuthzResult>()
        f.runner.run(request("https://app.test/api/advisor/queue", headers = mapOf("Cookie" to "sid=advisor")), listOf(customer), "Advisor", { true },
            ownerProfile = advisor, onResult = results::add)
        assertEquals(listOf("baseline", "identity:Customer", "unauth"), results.map { it.variant })
        val replay = results.single { it.variant == "identity:Customer" }
        assertEquals(AuthzResult.LIKELY_VIOLATION, replay.verdict)
        assertTrue(replay.expectation.startsWith("deny (lower role"))
        assertEquals(AuthzResult.ENFORCED, results.single { it.variant == "unauth" }.verdict)
    }

    @Test fun `another customer receiving the owner's identifying values is a likely horizontal violation`() {
        val f = AuthzFixture()
        val alice = jwt("alice-1001")
        f.response = { req -> if (req.headerValue("Authorization") == null) 401 to "denied" else 200 to "{\"owner\":\"alice-1001\",\"iban\":\"PL00\"}" }
        val owner = IdentityProfile("Alice", headers = mapOf("Authorization" to "Bearer $alice"), role = "customer")
        val bob = IdentityProfile("Bob", headers = mapOf("Authorization" to "Bearer ${jwt("bob-2002")}"), role = "customer")
        val results = mutableListOf<AuthzResult>()
        f.runner.run(request("https://app.test/api/statement", headers = mapOf("Authorization" to "Bearer $alice")), listOf(bob), "Alice", { true },
            ownerProfile = owner, onResult = results::add)
        val replay = results.single { it.variant == "identity:Bob" }
        assertEquals(AuthzResult.LIKELY_VIOLATION, replay.verdict)
        assertTrue(replay.note.contains("alice-1001"))
    }

    @Test fun `a resource that answers without credentials is labelled public instead of a violation`() {
        val f = AuthzFixture()
        f.response = { 200 to "{\"brand\":\"bank\"}" }
        val results = mutableListOf<AuthzResult>()
        f.runner.run(request("https://app.test/api/config", headers = mapOf("Cookie" to "sid=advisor")),
            listOf(IdentityProfile("Customer", headers = mapOf("Cookie" to "sid=c"), role = "customer")), "Advisor", { true },
            ownerProfile = IdentityProfile("Advisor", headers = mapOf("Cookie" to "sid=advisor"), role = "advisor"), onResult = results::add)
        assertEquals(AuthzResult.PUBLIC, results.single { it.variant == "identity:Customer" }.verdict)
    }

    @Test fun `roles survive re-observation and only known roles are accepted`() {
        val f = AuthzFixture()
        val id = f.catalog.observe(request(headers = mapOf("Cookie" to "sid=a")), "application/json", 200)!!
        f.catalog.setRole(id, "Advisor")
        f.catalog.setRole(id, "superuser")
        f.catalog.observe(request(headers = mapOf("Cookie" to "sid=a")), "application/json", 200)
        assertEquals("advisor", f.catalog.byId(id)!!.identity.role)
    }

    @Test fun `invite links are captured with their validation request and an ignored token is a likely violation`() {
        val f = AuthzFixture()
        val links = LinkCatalogs(f.config, f.scope)
        links.observe(request("https://app.test/join/Xk29fPq81z"), "text/html", 200)
        links.observe(request("https://app.test/api/meetings/Xk29fPq81z"), "application/json", 200)
        val link = links.invites().single()
        assertEquals("path", link.location)
        assertEquals(1, link.validations.size)
        val tester = LinkTester(f.api, f.config, f.scope)
        f.response = { req -> if (req.path().contains("Xk29fPq81z")) 200 to "{\"meeting\":\"m1\"}" else 404 to "{}" }
        val enforced = mutableListOf<AuthzResult>()
        tester.testInvite(link, { true }, { enforced += it })
        assertEquals(AuthzResult.ENFORCED, enforced.single { it.variant == "invite:token-altered" }.verdict)
        f.response = { 200 to "{\"meeting\":\"m1\"}" }
        val ignored = mutableListOf<AuthzResult>()
        tester.testInvite(link, { true }, { ignored += it })
        assertEquals(AuthzResult.LIKELY_VIOLATION, ignored.single { it.variant == "invite:token-altered" }.verdict)
        assertEquals("", ignored.single { it.variant == "invite:no-session" }.verdict.takeIf { it == AuthzResult.LIKELY_VIOLATION }.orEmpty())
    }

    @Test fun `token guessability distinguishes short numeric codes from long random tokens`() {
        assertTrue(Tokens.describe("123456").startsWith("Guessable"))
        assertTrue(Tokens.entropyBits("Xk29fPq81zAbCdEfGhIjKlMn") > 128)
        assertEquals(Triple("code", "48213377", "query"), Tokens.find("https://bank.test/visit?code=48213377"))
        assertNull(Tokens.find("https://bank.test/about"))
    }

    @Test fun `downloads are catalogued and another user's identical document is a likely violation`() {
        val f = AuthzFixture()
        val links = LinkCatalogs(f.config, f.scope)
        val ownerId = f.catalog.observe(request("https://app.test/api/me", headers = mapOf("Cookie" to "sid=alice")), "application/json", 200)
        val otherId = f.catalog.observe(request("https://app.test/api/me", headers = mapOf("Cookie" to "sid=bob")), "application/json", 200)
        links.observe(request("https://app.test/documents/42", headers = mapOf("Cookie" to "sid=alice")), "application/pdf", 200, "", ownerId)
        links.observe(request("https://app.test/static/app.js"), "application/javascript", 200)
        val artifact = links.artifacts().single()
        assertEquals("document (PDF)", artifact.kind)
        f.response = { req -> if (req.headerValue("Cookie") == null) 403 to "no" else 200 to "%PDF-alice-statement" }
        val results = mutableListOf<AuthzResult>()
        LinkTester(f.api, f.config, f.scope).testArtifact(artifact, f.catalog.snapshot(), f.catalog.byId(ownerId), { true }) { results += it }
        val bob = f.catalog.byId(otherId)!!.label
        assertEquals(AuthzResult.LIKELY_VIOLATION, results.single { it.variant == "artifact:$bob" }.verdict)
        assertEquals(AuthzResult.ENFORCED, results.single { it.variant == "artifact:no-credentials" }.verdict)
        assertTrue(results.any { it.variant == "artifact:id+1" })
        assertTrue(f.sent.any { it.path() == "/documents/43" })
    }

    @Test fun `link replays stop when scope is withdrawn`() {
        val f = AuthzFixture()
        val links = LinkCatalogs(f.config, f.scope)
        links.observe(request("https://app.test/join/Xk29fPq81z"), "text/html", 200)
        f.inScope = false
        val results = mutableListOf<AuthzResult>()
        LinkTester(f.api, f.config, f.scope).testInvite(InviteLink(1, "https://app.test/join/Xk29fPq81z", "join", "Xk29fPq81z", "path",
            java.time.Instant.now(), request("https://app.test/join/Xk29fPq81z")), { true }, { results += it })
        assertEquals(0, f.sent.size)
        assertEquals("SKIPPED", results.single().variant)
    }
}
