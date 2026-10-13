# TODO — comprehensive WebRTC pentesting from Burp

**1.2.0 update (2026-10-13):** The extension is self-contained. STUN/TURN tests,
HTTP/WebSocket scenarios and the default TLS engine run on the JVM inside Burp, and
Python is only needed for the optional SSLyze engine. TRN-04/05 verify forwarding
through a second allocation when no echo peer is supplied. Video banking work: session
roles with access verdicts, meeting-link and document/recording replays, XSS and
callback canaries with Burp Collaborator, screen-share and capture lifecycle,
postMessage review, the original-header audit, a banking preset and Burp-native
issues. Items below carry 1.2.0 notes where they changed.

Reviewed **2026-10-02** against the documented **1.0.5** baseline. This is an
implementation backlog, not a record of tests executed or vulnerabilities found
in a target. All checkboxes describe remaining work, including extensions to
partially implemented features.

The goal is one Burp workflow that discovers the RTC attack surface, prepares
test inputs, executes applicable checks, verifies effects, and produces evidence
and remediation. Browser hooks, Burp signaling handlers, managed protocol
runners, controlled peers, and lab harnesses should contribute to the same report.
Every applicable surface should have a test path and an explicit coverage status;
no finite scan can guarantee discovery of every WebRTC vulnerability.

## Review basis and current gaps

The Markdown inventory included case-insensitive extensions, hidden directories,
and ignored build output. Nine existing files were reviewed:

| Files | Review outcome |
| --- | --- |
| [README.md](README.md), [DOCS.md](DOCS.md) | Browser telemetry, SDP mutation/parser fuzzing, DataChannel payload fuzzing, HTTP authorization replay, ICE gathering, TCP TLS scans, reporting, and ten external command recipes already exist. Extend these instead of duplicating them. |
| [PLAN.MD](PLAN.MD) | T1–T8 are shipped. T9–T14 and E1–E6 are existing expansion ideas. Its permanent exclusions for signaling and media testing conflict with the broader product goal; companion backends can make these accessible from Burp. |
| [AGENTS.md](AGENTS.md) | Preserve scope gates, visible credentials, telemetry/report integration, paired extension/agent versioning, and the Gradle shell/`--no-daemon` convention. |
| `build/release-notes-1.0.5.md`, `build/reports/security-checklist-example.md` | Release and generated-report examples corroborate the documented gaps. Listing a methodology item does not implement its test. |
| `.kilo/worktrees/peridot-clownfish/{README.md,DOCS.md,PLAN.MD}` | Older 1.0.0 documents; compared shared text and reviewed their differences. They are historical copies, not the current feature baseline. |

Source spot-checks covered detectors, certificate analysis, Run All, extension
registration, the browser agent, and scan configuration. Existing uncommitted
`ScanPlan.kt`, `ProtocolScanConfig.kt`, and report/UI work were present; integrate
with that work rather than creating competing configuration or runners. An enum
entry or endpoint field is not evidence that a protocol test executes.

The linked [awesome-rtc-hacking list](https://github.com/EnableSecurity/awesome-rtc-hacking/blob/main/README.md)
is a useful research index. Its tools, primary research, protocol specifications,
and vendor documentation informed the test designs below. These designs are
recommendations; historical vulnerabilities do not establish that a current
deployment is vulnerable.

| Surface | Existing capability | Main missing capability |
| --- | --- | --- |
| Signaling and access control | HTTP M5 replay; passive metadata | Stateful WS/SSE testing, meaningful authorization assertions, call-state and consent tests |
| STUN/TURN | Browser gathering with supplied credentials | Credential matrix, actual forwarding, peer ACLs, integrity, allocation lifecycle |
| ICE and SDP | Observation and local parser/mutation checks | Trickle manipulation, session correlation, consent freshness, remote acceptance evidence |
| TLS and DTLS | Integrated TCP TLS; observed DTLS certificate/cipher | ICE-aware DTLS peer testing, binding enforcement, handshake races |
| SRTP/SRTCP/RTP | SDP/stats observations and external recipes | Packet authentication/replay, receiver evidence, gateway bleed/injection |
| DataChannels | Bounded payload sending and lifecycle | Negotiation/DCEP/SCTP, application authorization, remote effects |
| SFU/MCU and E2EE | Explicit report gaps | Tenant/track isolation, intermediary trust, membership and key lifecycle |
| Browser, API, recording | Permission outcomes; partial HTTP replay | Original-policy checks, token issuance, recording/storage and callback security |
| Resilience and native code | Local T8 loop; local SDP parsing | Server load measurements, media resilience, isolated native fuzzing |

## Priorities, execution modes, and implementation order

**P0:** prerequisites and misleading-result corrections. **P1:** common,
high-value misconfiguration and authorization checks. **P2:** broader protocol,
deployment-specific, and resilience coverage. **P3:** specialized native research.
These are delivery priorities, not vulnerability severities.

Execution modes used below:

- **Passive:** analyze captured traffic, telemetry, or supplied configuration.
- **Burp:** execute HTTP/WS/application scenarios through extension integrations.
- **Browser:** instrument and drive supported browser APIs.
- **Runner:** execute a managed protocol client from the Burp workflow.
- **Paired:** coordinate controlled peers/accounts and observe both sides.
- **Lab:** isolated crash, decoder, or intensive load harness; import evidence into Burp.

Run All should automatically execute selected checks whose prerequisites are
satisfied. Ask for missing accounts, destinations, or policy expectations once,
reuse them, and explain blocked checks in place. Keep an explicit stress/lab
profile for disruptive work instead of adding repeated confirmation dialogs to
ordinary selected tests.

| Delivery slice | Scope | Exit criterion | Status |
| --- | --- | --- | --- |
| 1 | FND-01/02/05/07; COR-01–06; LAB-05 | Reliable test registry, scope enforcement, evidence, and classifications | Completed in 1.1.0 |
| 2 | SIG-01–06; TRN-01–05; FND-03/04/06 | Automated signaling and TURN checks with positive/negative controls | Completed in 1.1.0 |
| 3 | SIG-07; ICE-01–05; SDP-01–04; DTL-02/03; MED-01/02 | Two-peer negotiation, consent, binding, and packet-security evidence | SDP-01 complete; open backlog |
| 4 | DCH, SFU, WEB, APP, SIP sections | Application and deployment packs with reusable scenarios | Open backlog |
| 5 | DTL-04/05; RES; LAB | Isolated resilience/native testing and reproducible imported results | Open backlog |

## Foundations for automatic testing

- [x] **FND-01 · P0 · Shared executable test registry.** Give each test a stable
  ID, applicability predicate, required inputs, backend capability, dependencies,
  expected effect, budgets, and evidence rules. Extend the existing `ScanPlan`
  direction. Run All, individual tabs, and M7 must use this registry. Done when an
  enabled test cannot disappear silently or be counted twice across report areas.
  *(Shipped in 1.1.0: 83 tests registered in `catalog.json` / `TestRegistry`).*

- [x] **FND-02 · P0 · Discovery with provenance.** Correlate application, account,
  page/frame/agent, peer, room, signaling connection, ICE listener, allocation,
  selected pair, and observation time. Parse captured configuration responses and
  WS messages as well as `RTCPeerConnection` configuration changes. Done when two
  concurrent apps cannot mix TURN credentials, certificates, or replay identities.
  *(Shipped in 1.1.0: `RtcCapture` captures WebSocket/HTTP signaling, decodes Socket.IO, nested SDP and ICE).*

- [x] **FND-03 · P1 · Managed protocol runner.** Reuse the TLS runner's structured
  input/output, process cancellation, runtime checks, and bounded output design
  for STUN/TURN, WS/SIP, DTLS, and media adapters. Support Windows-hosted Burp and
  an explicitly configured companion where platform support requires it. Pin
  versions and document licenses. Done when tests run and return structured
  evidence from Burp without copying shell commands; edited recipes remain text.
  *(Shipped in 1.1.0: `protocol_runner.py` / `ProtocolRunner.kt` with JSON-lines IPC).*

- [x] **FND-04 · P1 · Controlled peer and two-identity harness.** Provide synthetic
  audio/video markers, DataChannel echo, TURN echo destinations, separate browser
  contexts, and receiver counters. Learn a successful join/publish/subscribe/leave
  scenario and replay it with bounded mutations. Done when a tester can prepare
  one valid call and run applicable scenarios without rebuilding call setup for
  every test. Record required user gestures as explicit prerequisites.
  *(Shipped in 1.1.0: Multi-identity scenario harness with positive controls and response assertions).*

- [x] **FND-05 · P0 · Scope every network leg.** Preserve `ScopeGate` + host
  allow-list + `injectionEnabled` for all active backends. Gate signaling URLs,
  resolved addresses, TURN listeners AND relay destinations, redirect targets,
  alternate servers, media peers, and callbacks. Recheck on scope changes and
  before follow-up traffic; stop runners and release allocations. A discovered
  third-party service or ICE candidate never inherits authorization automatically.
  *(Shipped in 1.1.0: `NetworkAuthorization.kt` and parent grants for every network leg).*

- [x] **FND-06 · P1 · Dependency-aware Run All.** Show Ready, Needs identity,
  Needs live call, Needs peer, Unsupported backend, and Out of scope. Refresh
  expiring inputs, schedule calls before dependent probes, reuse successful
  controls, and offer rerun-failed/rerun-after-fix. Done when interrupted work has
  resumable results and tests are not repeated against every page unnecessarily.
  *(Shipped in 1.1.0: `AssessmentController` status reporting and Run All integration).*

- [x] **FND-07 · P0 · Evidence and outcome contract.** Record test/run IDs,
  exact inputs, backend/tool versions, timestamps, controls, transmitted cases,
  observed effects, cleanup, and limitations. Separate capability, execution,
  security outcome, confidence, and severity. HTTP 200, WS 101, a local API return,
  or a TURN permission alone cannot confirm impact. Keep absent, timed-out,
  unsupported, and inconclusive results distinct from a demonstrated rejection.
  *(Shipped in 1.1.0: `TestOutcome` and `TestEvidence` contracts).*

- [ ] **FND-08 · P1 · Complete Burp workflow integration.** Add RTC-specific
  context actions for observed HTTP/WS messages, insertion points for tokens,
  room IDs, SDP and candidates, and deduplicated Burp issues with reproduction and
  remediation. Import companion results into the same engagement. Done when the
  tester can move from observation to test to issue without re-entering evidence.
  *(1.2.0 partial: deduplicated WebRTC issues are added to Burp's Issues list with evidence, an Intruder canary payload source is registered, and context actions stage requests in Access control. RTC-specific scanner insertion points remain open.)*

## Correct existing analysis before expanding its reach

- [x] **COR-01 · P0 · Fix IP-privacy classification.** `RunAllController.reviewPrivacy`
  currently gathers public addresses without excluding relay candidates and uses
  a global `any` relay-policy check. Distinguish relay infrastructure from client
  host/srflx/prflx addresses, local observation from transmission, and each peer's
  effective policy. Normal public connectivity is not automatically a privacy
  violation. Done when relay-only and mixed-peer fixtures cannot produce a user-IP
  finding or blanket privacy pass. [IP handling requirements](https://www.rfc-editor.org/rfc/rfc8828.html).
  *(Shipped in 1.1.0: `EvidenceAnalysis.privacy` evaluates per-peer policies and excludes relay infrastructure).*

- [x] **COR-02 · P0 · Restrict ICE reuse findings to actual restarts.**
  `Detectors.iceCredentialReuse` compares successive offers; ordinary renegotiation
  may retain credentials. Parse session/media inheritance and non-adjacent
  credential lines instead of the current short-distance regex. Correlate restart
  requests and ICE generations; check both ufrag and password rotation. Done when
  ordinary renegotiation/BUNDLE reuse is accepted and a failed deliberate restart
  is detected. Treat character diversity as a heuristic, not measured entropy.
  [ICE restart rules](https://www.rfc-editor.org/rfc/rfc8445.html#section-9).
  *(Shipped in 1.1.0: `EvidenceAnalysis.restartIssues` checks deliberate `iceRestart` flag and inheritance).*

- [x] **COR-03 · P0 · Bind certificates to the correct session.**
  `reviewStats` currently pools SDP fingerprints and deduplicates certificates by
  fingerprint. Match certificate role, peer, transport/MID, negotiation generation,
  and the declared algorithm. A match in another room must not satisfy binding;
  missing evidence must remain unknown. Done when swapped peer certificates fail
  correlation and simultaneous transports/algorithms work correctly.
  [SDP fingerprint semantics](https://www.rfc-editor.org/rfc/rfc8122.html).
  *(Shipped in 1.1.0: `EvidenceAnalysis.binding` matches role, peer, transport, generation, and MIDs).*

- [x] **COR-04 · P0 · Apply SDP semantics per media section.** Replace global
  fingerprint/codec/attribute checks with structured session/media inheritance,
  active versus rejected `m=` sections, BUNDLE groups, and local/remote direction.
  Payload type values are scoped; `m=application` is not RTP media. Done when a
  fingerprint on one transport cannot hide another transport's missing binding,
  and codec parameters cannot leak between media sections or peers. Handle
  bundle-only port-zero sections according to [BUNDLE semantics](https://www.rfc-editor.org/rfc/rfc9143.html),
  rather than automatically treating every zero port as rejection.
  *(Shipped in 1.1.0: `SdpDocument.kt` and `EvidenceAnalysis.kt` per RFC 9143).*

- [x] **COR-05 · P0 · Correct crypto and capability verdicts.** Treat self-signed
  DTLS certificates as normal fingerprint-based identities; distinguish their
  validity metadata from HTTPS PKI failures. SDES exposes keys to signaling
  participants but HTTPS may still protect signaling in transit. Standard SRTP
  HMAC-SHA1 profiles, `ice-lite`, mDNS, codec names, and certificate reuse alone are
  not confirmed vulnerabilities. Require negotiation/policy context and retain
  existing missing-stats safeguards. [WebRTC trust model](https://www.rfc-editor.org/rfc/rfc8827.html).
  *(Shipped in 1.1.0: SDES is marked WARN/review; self-signed DTLS certificates recognized as normal WebRTC identities).*

- [x] **COR-06 · P0 · Reconcile the roadmap and labels.** Rename T8 to describe
  its local negotiation loop: it sends no server signaling. Fix PLAN's older T8
  server-rate-limit promise and Gradle examples that omit the required wrapper.
  Replace permanent product exclusions with backend requirements as features land.
  Reconcile the claim that credentials live only in the project with documented
  telemetry/clipboard/export behavior. Preserve full credentials as AGENTS requires.
  Make TODO the open backlog and retain PLAN's shipped history without duplicates.
  *(Shipped in 1.1.0: Renamed to "Local negotiation loop (T8)"; full credentials preserved; docs reconciled).*

## Signaling, identity, rooms, and call-state attacks

- [x] **SIG-01 · P1 · Burp · Native WebSocket capture and RTC decoding (T9).**
  Register the available Montoya WS handlers, retain upgrade/auth/Origin/subprotocol
  metadata, and correlate messages and reconnects. Decode bounded JSON, nested or
  escaped SDP, trickle ICE, Socket.IO envelopes, and confirmed SIP; preserve binary
  messages with decoder plugins. Done when WS observations populate the same
  endpoint, credential, identity, and scenario inventory as HTTP.
  *(Shipped in 1.1.0: `RtcCapture.kt` handles WebSocket created, frames, and decoding).*

- [x] **SIG-02 · P1 · Burp · Real authentication matrix.** Extend M5 to HTTP and
  WS with valid, absent, malformed, expired, revoked, and alternate-user contexts.
  Capture auth in cookies, headers, query/body fields, subprotocols, and the first
  application message. Assert protected data/action outcomes rather than status
  codes. Done when leaving a body token behind cannot label a request unauthenticated.
  *(Shipped in 1.1.0: `protocol_runner.py` / `Scenario` supports header/cookie/query/body token substitution).*

- [x] **SIG-03 · P1 · Burp + Paired · Cross-site WebSocket hijacking.** Compare
  allowed, untrusted, null, and absent Origin handshakes; test origin-parser edge
  cases. Confirm sensitive read/write access from a real controlled browser origin
  with its actual cookie/SameSite rules. A forged Origin accepted by a raw client
  is only a lead. [OWASP WebSocket guidance](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).
  *(Shipped in 1.1.0: Scenario WS-open with Origin variants; browser SameSite guidance).*

- [x] **SIG-04 · P1 · Burp + Paired · Per-message and cross-tenant authorization.**
  Substitute room, participant, producer, consumer, stream, recording, and tenant
  identifiers across established connections. Exercise join, invite, publish,
  subscribe, kick, mute, transfer-host, and record operations using guest/member/
  moderator roles. Done when unauthorized delivery or a forbidden state change is
  observed in the second identity, with a valid-role control.
  *(Shipped in 1.1.0: Paired scenario runner with role/identifier substitution and effect assertion).*

- [x] **SIG-05 · P1 · Burp + Paired · Session lifecycle and token binding.**
  Test logout, expiry, kick/ban, password/session revocation, refresh, reconnect,
  duplicate identity, and invitation reuse. Check issuer/audience/tenant/room/role
  claims where tokens support them. Specify the application's expected lifetime;
  token expiry does not universally mandate ending an established call. Verify
  whether both fresh admission and existing media/data privileges meet that policy.
  *(Shipped in 1.1.0: Scenario token binding assertions and lifecycle tests).*

- [x] **SIG-06 · P1 · Burp + Paired · Admission and enumeration.** Test waiting
  room and host approval, locked rooms, meeting passwords, invite expiry, guest
  restrictions, and reconnect paths. Bound room/account enumeration to supplied
  fixtures and compare response content/timing. Done when identifier guessability
  is separated from demonstrated unauthorized admission or information exposure.
  *(Shipped in 1.1.0: Bounded scenario testing for waiting rooms, locked rooms, and password gates).*
  *(1.2.0: meeting / invite links are also tested directly — altered, removed and session-less token replays, guessability estimate and post-meeting recheck.)*

- [ ] **SIG-07 · P1 · Paired · Call-state and user-consent regression suite.**
  Reorder/replay offer, answer, candidate, renegotiation, and hangup messages before
  acceptance, after rejection, during simultaneous calls, and after termination.
  Include hold, mute, track replacement, and multi-device transitions. Verify
  forbidden transmission with synthetic media at the receiving peer; permission
  granted to a browser is not consent to every call. Inspired by Project Zero's
  [calling state-machine research](https://projectzero.google/2021/01/the-state-of-state-machines.html).

- [ ] **SIG-08 · P1 · Burp · Stateful signaling fuzzer (T10).** Mutate message
  type, field types, duplicate/missing fields, nesting, bounded lengths, SDP,
  candidates, sequence numbers and transaction IDs within a recorded valid flow.
  Include replay, stale messages, ordering and controlled races. Done when the
  remote server/client response and recovery are captured separately from M3+'s
  local parser result; minimize and retain reproducible failing cases.

- [ ] **SIG-09 · P2 · Burp + Paired · Injection and unsafe message handling.**
  Use RTC insertion points for chat, display names, SDP attributes, room metadata,
  captions, file metadata and gateway fields. Integrate Burp checks for XSS,
  SQL/command/template injection, unsafe deserialization and prototype pollution
  where the receiving technology applies. Require sink execution, a controlled
  callback, or another concrete effect; reflected strings alone are not proof.
  *(1.2.0 partial: self-reporting XSS canaries prove stored script execution in any instrumented page, with Collaborator for uninstrumented pages and reflection tracking in HTTP/WebSocket traffic. SQL/command/template and deserialization cases remain open.)*

- [ ] **SIG-10 · P2 · Burp · SSE, polling, and HTTP signaling parity.** Apply
  authentication, CORS/CSRF, subscription authorization, reconnect, Last-Event-ID,
  cache isolation and token-leakage tests to non-WS transports. Done when the
  same room scenario remains testable after transport fallback, and public event
  streams are not confused with protected participant streams.

## STUN/TURN authentication, relay abuse, and configuration

Protocol baselines: [TURN RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html)
and [STUN RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html). The following are
proposed test cases built around those protocols and the cited research.

- [x] **TRN-01 · P1 · Runner · Listener/transport inventory.** Test selected
  observed UDP, TCP, TLS and supported DTLS listeners over IPv4/IPv6, including
  nonstandard ports. Record STUN responses, realm, software, redirects, and
  allocation support. Distinguish client-to-server transport from UDP versus
  RFC 6062 TCP relaying. Unauthenticated STUN Binding success is expected in many
  deployments and is not an open TURN relay finding.
  *(Shipped in 1.1.0: `protocol_runner.py` / `ProtocolRunner.kt` STUN inventory).*

- [x] **TRN-02 · P1 · Runner · Automated TURN authentication matrix.** Compare
  valid, absent, incorrect, known-expired and revoked credentials using fresh
  allocations; exercise realm/nonce and stale-nonce handling. Separate Allocate,
  Refresh, permission and transfer results. Keep a valid positive control and
  challenge transcript. Done when a failed browser gather cannot be mistaken for
  proven authentication enforcement, and credential expiry is measured or supplied.
  *(Shipped in 1.1.0: `protocol_runner.py` / `ProtocolRunner.kt` authentication matrix with MESSAGE-INTEGRITY checks).*

- [ ] **TRN-03 · P1 · Burp + Runner · Credential issuance and reuse policy.**
  Test the application's TURN-credential API for missing auth, cross-user/tenant
  access, excessive lifetime, shared static credentials, caching, and continued
  issuance after logout. Distinguish expected browser-visible temporary TURN
  passwords from leaked server HMAC/admin secrets. Validate reuse against the
  stated service policy; a working credential outside one call is not automatically
  a bug. Record issuer, subject, realm, expiry and exact endpoint association.

- [x] **TRN-04 · P1 · Runner + Paired · Peer ACL/SSRF and real forwarding.**
  Compare explicitly selected allowed and denied destinations using actual echo
  receipts. Cover loopback, private/link-local IPv4, IPv6 loopback/ULA/link-local,
  mapped/translated addresses and deployment-specific NAT64 routes. Use test
  services or metadata emulators for restricted destinations. A successful
  permission is not proof of reachability. [Slack TURN research](https://www.enablesecurity.com/blog/slack-webrtc-turn-compromise-and-bug-bounty/)
  and [coturn's topology-dependent ACL advisory](https://github.com/coturn/coturn/security/advisories/GHSA-2x4g-wx24-48m4).
  *(Shipped in 1.1.0: `protocol_runner.py` echo transfer with synthetic marker verification).*

- [x] **TRN-05 · P1 · Runner + Paired · All relay data paths.** Exercise
  CreatePermission/Send indications, ChannelBind/ChannelData, and TCP
  Connect/ConnectionBind where supported. Test delivery without permission,
  permission expiry, cross-allocation channel reuse, and differences between
  paths/transports/address families. Include bounded transfer to a controlled
  public peer for open-relay/bandwidth-abuse review. Legitimate unrestricted
  peer-to-peer relay capability requires policy context before being a finding.
  *(Shipped in 1.1.0: `protocol_runner.py` ChannelBind and Send/Data paths with echo verification).*

- [ ] **TRN-06 · P2 · Runner · STUN integrity and parsing.** Test absent/bad
  MESSAGE-INTEGRITY, incorrect transactions, duplicate/unknown attributes,
  lengths/padding, and semantic attributes after the integrity boundary. Keep
  CRC FINGERPRINT distinct from keyed authentication. Measure changed allocation
  behavior as evidence; use controlled sessions for tampering. Coturn's
  [2026 integrity-boundary advisory](https://github.com/coturn/coturn/security/advisories/GHSA-5538-7cxj-5jcc)
  illustrates why this needs a regression case; its on-path plaintext-transport
  prerequisites must remain attached to that specific finding.

- [x] **TRN-07 · P2 · Runner + Paired · Allocation ownership and cleanup.**
  Test cross-account refresh/delete/bind attempts, reservation tokens if supported,
  lifetime limits, logout-versus-allocation policy, reconnect behavior, and
  releases after Stop/timeouts. Done when the harness can distinguish accepted
  allocation state from actual packet transfer and leave no test allocation active.
  *(Shipped in 1.1.0: `protocol_runner.py` allocation refresh and release handling).*

- [ ] **TRN-08 · P2 · Runner · Quotas and amplification measurements.** Run
  bounded per-account allocation/bandwidth/concurrency tests with service-health
  controls. Measure request/response size ratios and unauthenticated response
  behavior using owned endpoints; reflection susceptibility needs the appropriate
  lab network, not an Internet spoofing campaign. Record enforced limits and
  recovery; a short run cannot prove the absence of rate limiting.

- [ ] **TRN-09 · P1 · Passive + Runner · Optional coturn configuration audit.**
  Import supplied config and deployment context to review auth mode, REST secret
  handling, peer deny/allow precedence, IPv6 restrictions, multicast/loopback,
  relay exposure, quotas, TLS, admin listeners and database access. Correlate
  settings with observed behavior and mark inaccessible configuration unknown.
  Use the [upstream configuration reference](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf)
  for the actual deployed version; do not prescribe one release's defaults to all.

## ICE, candidate manipulation, and privacy

- [ ] **ICE-01 · P1 · Browser + Paired · Privacy policy matrix.** Compare normal
  versus relay-only operation across IPv4/IPv6, permission states, TURN failure,
  network changes and tester-selected VPN/proxy arrangements. Correlate gathered,
  signaled, received and selected candidates, including related addresses and
  mDNS. Verify actual unauthorized direct connectivity or disclosure against the
  privacy requirement; missing candidates and a configuration flag cannot prove
  protection. [RFC 8828](https://www.rfc-editor.org/rfc/rfc8828.html).

- [ ] **ICE-02 · P1 · Browser + Burp + Paired · Trickle ICE manipulation.**
  Extend M3 beyond embedded SDP to `addIceCandidate` and signaling messages.
  Mutate controlled destination, MID/m-line association, priority, protocol and
  username fragment; replay stale/cross-room candidates and end-of-candidates.
  Verify the peer's actual connectivity checks and authorization. A candidate
  accepted by a browser parser does not establish access to that destination.

- [ ] **ICE-03 · P2 · Runner + Paired · ICE authentication and nomination.**
  Test wrong/missing short-term credentials, stale generations, transaction
  mismatches, role conflicts, premature nomination and peer-reflexive candidates.
  Verify authenticated selected-pair behavior and rejection counters. Keep ICE
  authentication distinct from STUN discovery and TURN account auth.
  [ICE specification](https://www.rfc-editor.org/rfc/rfc8445.html).

- [ ] **ICE-04 · P1 · Paired · Consent freshness.** With an established controlled
  call, stop answering consent requests while retaining packet capture. Verify
  application traffic ceases on the affected tuple after the specified consent
  expiry; test forged/stale replies and supported revocation behavior. Keep the
  healthy call as a control. Record timing, tuple and received packets, not just
  connection-state events. [RFC 7675's 30-second expiry](https://www.rfc-editor.org/rfc/rfc7675.html#section-5.1).

- [ ] **ICE-05 · P2 · Paired · Restart and path migration.** Deliberately restart
  ICE, fail a relay, switch interfaces, and reconnect after room removal. Verify
  credential rotation, rejection of stale candidates/credentials, selected-pair
  changes and continued privacy/authorization policy. Do not assume every ICE
  restart also requires a new DTLS association; report the actual key lifecycle.

## SDP and negotiation beyond local parser acceptance

- [x] **SDP-01 · P1 · Browser · Complete hook coverage.** Cover implicit
  `setLocalDescription()`, `setConfiguration`, transceivers, rollback and supported
  legacy callback paths; keep each mutation attached to its exact operation.
  Preserve valid baselines and restore settings after a run. Done when supported
  application negotiation paths no longer silently bypass mutation/telemetry.
  *(Shipped in 1.1.0: `webrtc-agent.js` hooks implicit `setLocalDescription`, `addIceCandidate`, rollback, legacy callbacks).*

- [ ] **SDP-02 · P1 · Burp + Paired · Remote security enforcement matrix.**
  Replay altered fingerprints, setup roles, ICE credentials, media directions,
  transport profiles, SDES attributes and unexpected tracks through actual
  signaling. Distinguish local rejection, remote rejection, completed handshake,
  and received media. A removed fingerprint causing a local exception proves only
  local validation; it does not test the media server.

- [ ] **SDP-03 · P2 · Paired · BUNDLE and stream identity confusion.** Mutate
  MID, MSID, SSRC, RID/simulcast, extension mappings, BUNDLE membership, rtcp-mux,
  rejected sections and reused payload types within valid sessions. Check whether
  tracks are routed to another participant or acquire unintended permissions.
  Include rollback/glare and stale answers. Done when receiver track identity,
  session ownership and media markers establish the outcome.

- [ ] **SDP-04 · P2 · Browser + Paired · Codec negotiation policy (T14).**
  Compare capabilities, advertised preferences, negotiated codec and actual
  encoder/decoder use. Test forbidden codecs/profiles, malformed fmtp, RTX/FEC
  association, and policy fallback. A codec preference change is not inherently
  an encryption downgrade; report a security issue only against a relevant
  requirement or demonstrated parser effect. [WebRTC API](https://www.w3.org/TR/webrtc/).

## TLS, DTLS, and certificate enforcement

- [ ] **DTL-01 · P1 · Runner · Finish automatic TCP TLS coverage.** Queue the
  selected HTTPS/WSS, TURN-TLS and applicable SIP-TLS listeners discovered in an
  engagement using the existing scanner. Preserve SNI, path-derived scope and
  each resolved endpoint; report trust, protocol/cipher and vulnerability probes
  separately. Compare listener aliases/backends where selected. Do not count a
  successful TCP TLS scan as DTLS media coverage.
  *(1.2.0 partial: the built-in JVM TLS engine runs without Python and covers SSL 3.0 to TLS 1.3, TLS 1.2 suites and certificates; automatic queuing of every discovered listener remains open.)*

- [ ] **DTL-02 · P1 · Runner + Paired · ICE-aware DTLS capability testing.**
  Establish authorized signaling and ICE before testing media DTLS. Enumerate
  supported versions/ciphers and SRTP protection profiles, and compare with
  negotiated values under both DTLS roles. A silent UDP socket or a DTLS alert
  without completed ICE is inconclusive. Done when a known-good call and the
  exact reachable handshake stage accompany every negative case.

- [ ] **DTL-03 · P1 · Paired · Fingerprint and identity negative tests.**
  Present a different certificate from the one committed in signaling; try stale
  session bindings, missing/wrong fingerprint and certificate changes during
  renegotiation. Verify protected media/data is rejected and the correct control
  connects. Also test substitution of both signaling identity and certificate
  where the app claims peer identity protection; valid DTLS alone does not bind
  an account to the intended caller. [RFC 8827](https://www.rfc-editor.org/rfc/rfc8827.html).

- [ ] **DTL-04 · P2 · Lab + Paired · Handshake race and state resilience.**
  Add bounded DTLS ClientHello-before/alongside-legitimate-peer cases, wrong
  source, replayed flights, fragmentation/reassembly and failed-handshake recovery.
  Measure whether the authorized call is prevented and whether other calls
  recover. Keep this outside ordinary passive analysis.
  [Enable Security's DTLS race research](https://www.enablesecurity.com/blog/novel-dos-vulnerability-affecting-webrtc-media-servers/).

- [ ] **DTL-05 · P2 · Passive + Lab · Version-aware crypto regression cases.**
  Map server crypto dependencies to vendor advisories using reliable version/build
  evidence, then offer isolated regression fixtures. CVE-2022-0778 is an example
  of certificate parsing reachable through a completed RTC setup, not a generic
  vulnerability in every browser or server. Require vulnerable/patched controls,
  CPU/crash evidence and exact dependencies for an active finding.
  [Original WebRTC reproduction](https://www.enablesecurity.com/blog/exploiting-cve-2022-0778-in-openssl-vs-webrtc-platforms/).

## SRTP, SRTCP, RTP, RTCP, and media gateways

These require a packet-capable peer and receiver evidence. Generic UDP sends to
an ICE candidate do not provide these tests. The protocol baseline is
[SRTP RFC 3711](https://www.rfc-editor.org/rfc/rfc3711.html).

- [ ] **MED-01 · P1 · Runner + Paired · Authentication and replay protection.**
  With controlled session keys, test modified payload/header/tag, missing or
  truncated tags, wrong keys, duplicate packets and replay-window boundaries.
  Exercise SRTP and SRTCP independently in each direction, including sequence
  rollover and out-of-order valid controls. Require receiver acceptance/drop
  counters or decoded synthetic markers; ciphertext seen on the wire is insufficient.

- [ ] **MED-02 · P2 · Paired · Keys, epochs, and stream isolation.** Test stale
  media after teardown/reconnect/rekey, key separation between directions/rooms,
  SSRC/context collisions and counter/nonce continuity where observable. Associate
  each packet with its transport and key epoch. Distinguish intentional DTLS
  association reuse from unsafe key/counter reuse; avoid conclusions from matching
  certificate fingerprints alone.

- [ ] **MED-03 · P1 · Runner + Paired · RTP bleed and injection at gateways.**
  For confirmed plaintext RTP legs, compare nominated versus unexpected senders,
  source-address latching and returned media; test injection with synthetic
  markers into an owned call. Verify gateway legs independently of browser SRTP.
  Require media endpoint/port validation, not SDP placeholder port 9. Adapt the
  existing SIPPTS recipe and the [DVRTC RTP-bleed lab](https://github.com/EnableSecurity/DVRTC).

- [ ] **MED-04 · P2 · Runner + Paired · RTP/RTCP control and demultiplexing.**
  Mutate bounded RTP extensions, CSRC/SSRC, payload types, sequence/timestamps,
  padding and RTCP feedback/BYE lengths in established test sessions. Test forged
  feedback, cross-stream confusion and STUN/DTLS/RTP demultiplexing boundaries.
  Validate receiver behavior and service health; arbitrary acceptance or packet
  loss is a triage signal until an integrity, routing, crash or resource effect is shown.

- [ ] **MED-05 · P2 · Runner · PCAP and media-evidence integration.** Add
  managed capture/import with endpoint filters, packet timestamps and supported
  test-key imports. Link selected pairs, DTLS sessions, SRTP/SRTCP streams and
  receiver counters to test IDs. Record capture drops, missing keys and unsupported
  dissection. Keep encrypted payloads marked opaque when they cannot be decoded;
  TShark protocol recognition is not proof of successful application delivery.

## DataChannel and SCTP

- [ ] **DCH-01 · P1 · Browser + Paired · Negotiation matrix (T11).** Test
  ordered/unordered delivery, partial reliability, invalid parameter combinations,
  negotiated-ID collisions, label/protocol lengths, binary/text types, stream
  closure/reset and reopening. Compare both endpoints' channel state and receipt.
  Retain M4 budgets and short-lived-channel support.
  [DataChannel specification](https://www.rfc-editor.org/rfc/rfc8831.html).

- [ ] **DCH-02 · P1 · Paired · Message authorization and injection.** Test
  room/role enforcement for chat, file transfer, commands, collaborative actions
  and data topics; replay across participants and after removal. Exercise schemas,
  duplicate/out-of-order messages, and bounded file-name/path/type handling where
  supported. Done when a send result is paired with an observed remote effect or
  rejection, including applications where data is relayed by an SFU.

- [ ] **DCH-03 · P2 · Browser + Paired · Backpressure and channel quotas.**
  Measure `bufferedAmount`, negotiated message-size limits, concurrent channels,
  receiver processing, memory and recovery under bounded bursts. Include
  send-after-close and slow consumer scenarios. Record whether media quality is
  affected, release resources on Stop, and avoid equating sender exceptions with
  remote vulnerability. [WebRTC API limits and behavior](https://www.w3.org/TR/webrtc/).

- [ ] **DCH-04 · P3 · Lab · DCEP/SCTP packet harness.** Add authenticated
  SCTP-over-DTLS tests for malformed establishment messages, PPIDs, stream IDs,
  fragmentation, partial reliability, resets and reassembly limits. JavaScript
  DataChannel payload fuzzing cannot craft all these protocol fields. Done when
  corpus, backend build, receiver traces and minimized failures are importable.
  [SCTP transport model](https://www.rfc-editor.org/rfc/rfc8831.html).

## SFU, MCU, gateway, and end-to-end encryption

- [ ] **SFU-01 · P1 · Passive + Paired · Architecture and adapter packs.**
  Record confirmed P2P/SFU/MCU/gateway roles from actual signaling, configuration
  or server evidence. Add versioned scenario adapters for common stacks while
  retaining a generic recorded workflow. Each adapter defines resource IDs,
  token grants, join/publish/subscribe and cleanup. Hostnames alone cannot establish
  topology or identify which hop can decrypt media.

- [ ] **SFU-02 · P1 · Paired · Media and data authorization.** Use two tenants
  and publisher/subscriber/guest/moderator roles to attempt cross-room track
  subscription, unauthorized publication, impersonated identities, hidden tracks,
  screen sharing and data access. Continue after permission changes and removals.
  Require decoded synthetic markers or verified remote actions; admission to
  signaling alone does not prove media access.

- [ ] **SFU-03 · P2 · Paired · Routing and gateway trust.** Test track/stream
  reassignment, stale consumer IDs, reconnect races, SFU migration, transcoding,
  recording bots and SIP bridge membership. Verify forwarding cannot cross tenant
  or conference boundaries. Validate each boundary with identities and receiver
  markers, including when encryption legitimately terminates at a gateway.

- [ ] **SFU-04 · P1 · Passive + Paired · Verify E2EE claims.** Detect supported
  encoded-transform/E2EE mechanisms and document which components hold keys.
  Test key-service authorization, join/leave rotation, removed-member access,
  wrong keys, integrity failure, and plaintext fallback. A DTLS-SRTP connection
  to an SFU alone cannot demonstrate E2EE. Do not flag absence of E2EE unless
  required by the application's security model.
  [SFrame's intermediary trust model](https://www.rfc-editor.org/rfc/rfc9605.html).

- [ ] **SFU-05 · P2 · Paired · E2EE downgrade and sender identity.** Compare
  participants with mixed capabilities, worker/transform failure, renegotiation,
  recording enabled and membership changes. Check whether UI claims match actual
  protection. Test counter/key-ID reuse and sender attribution when inspectable;
  SFrame's symmetric authentication does not by itself provide per-sender
  authenticity. Require application-specific identity/key evidence.
  [SFrame security considerations](https://www.rfc-editor.org/rfc/rfc9605.html#section-7).

## Browser permissions and client security

- [x] **WEB-01 · P1 · Passive + Browser · Original-policy capture.** Preserve
  original CSP, Permissions-Policy, frame rules, CORS, cookies and secure-context
  metadata before injection changes them. Run origin/XSS/framing checks in an
  unmodified comparison context. Done when stripped CSP or injected agent behavior
  cannot be reported as the target's native policy or an exploitable XSS result.
  *(Shipped in 1.2.0: `PolicyAudit` reviews the original headers captured before injection — framing, CSP, Permissions-Policy, HSTS, session cookies, CORS null and meeting-token Referrer leaks.)*

- [ ] **WEB-02 · P2 · Browser + Paired · Permissions and capture lifecycle
  (T12).** Extend getUserMedia telemetry to display capture, device enumeration
  exposure, cross-origin frames, permission denial/revocation, track stop and
  navigation. Observe policy enforcement and whether protected transmission
  continues after the user-facing stop action, using synthetic tracks. Keep user
  gestures and browser-specific restrictions explicit; avoid collecting real
  microphone/camera contents for a generic scan.
  *(1.2.0 partial: `getDisplayMedia` outcomes and surfaces, track stop/end, capture still live after the last peer closes, permission states, permission policy and device-label exposure. Revocation during a call and cross-origin frames remain open.)*

- [ ] **WEB-03 · P2 · Browser · Cross-origin integration.** Test postMessage
  origin/source validation, embedded call controls, SDK callbacks, service-worker
  caches and third-party script access to signaling/media controls. Correlate with
  actual app roles and trusted parent origins. Support Chromium, Firefox and
  WebKit capability matrices; an unavailable API is a coverage limitation, not
  a successful security test.
  *(1.2.0 partial: message listeners without origin checks, cross-origin messages received and wildcard postMessage use are recorded; SDK callbacks, service workers and multi-browser matrices remain open.)*

## Supporting APIs, recordings, infrastructure, and streaming

- [ ] **APP-01 · P1 · Burp · Token minting and administrative surfaces.**
  Test RTC token endpoints for caller-controlled room/tenant/identity/role grants;
  check observed admin/monitor/debug APIs and supplied config for unintended
  exposure. Distinguish public SDK keys from signing/admin secrets. Add tailored
  assertions for [LiveKit grants](https://docs.livekit.io/frontends/reference/tokens-grants/)
  and [Janus API authentication](https://janus.conf.meetecho.com/docs/auth.html),
  accounting for deployment/version differences rather than assuming defaults.

- [ ] **APP-02 · P1 · Burp + Paired · Recording and artifact access.** Test
  recording start/stop roles, participant indicators, cross-tenant listing and
  download, transcript/caption/chat artifacts, signed URL expiry, sharing,
  deletion and cache persistence. Use owned fixtures. Record storage/encryption/
  retention evidence when supplied; technical tests alone cannot certify legal
  or regulatory compliance.
  *(1.2.0 partial: Documents & recordings replays captured downloads across sessions and roles, without credentials and with neighbouring IDs, and reports signed-link lifetime. Recording start/stop roles, listing and deletion remain open.)*

- [ ] **APP-03 · P2 · Burp + Paired · Callbacks, webhooks and fetchers.**
  Test webhook signature/timestamp/replay validation and authorization for room,
  recording and billing events. Check user-controlled recording output, media
  import, transcription and callback URLs for SSRF with an owned callback or
  private-service emulator. Follow redirects only within the selected test scope.
  Link each received callback to the initiating test.
  *(1.2.0 partial: Collaborator-backed callback canaries for webhook, export and import fields; signature/replay validation of webhooks remains open.)*

- [ ] **APP-04 · P1 · Passive · Component and advisory inventory (T13).**
  Collect defensible browser, SDK, SFU, TURN, gateway, codec and crypto-library
  version evidence from supplied inventories, bundles or banners. Match maintained
  vendor advisories with affected configuration and fixed-build information.
  Mark uncertain fingerprints and version-only matches as leads; backports and
  disabled features can change applicability. Include source URLs and review dates.

- [ ] **APP-05 · P2 · Burp + Paired · WHIP and WHEP adapter.** For detected
  endpoints, test bearer/stream-key authorization, session-URL ownership, POST/
  PATCH/DELETE lifecycle, trickle ICE, conditional requests, CORS, redirects,
  discovered ICE-server configuration and cleanup. Verify termination or stream
  access using a second identity. WHIP has an RFC; pin WHEP behavior to the
  actual deployed specification/version rather than assuming equivalence.
  [WHIP security considerations](https://www.rfc-editor.org/rfc/rfc9725.html#section-5).

- [ ] **APP-06 · P2 · Passive + Burp · Provider-specific assessment packs.**
  When provider use and account scope are established, add SDK token grants,
  public serverless functions/assets, webhook controls and exposed configuration
  checks. Keep provider discovery, credential acquisition and authorized tests
  distinct. Consider the awesome list's Twilio scanner as an adapter candidate;
  account access and the installed tool's actual capabilities are prerequisites.

## SIP and telephony gateways — conditional on actual use

Only enable these cases for confirmed SIP/SIP-over-WS or a tester-declared
gateway. SDP alone is not SIP evidence. Use
[RFC 7118](https://www.rfc-editor.org/rfc/rfc7118.html) for SIP-over-WebSocket
transport requirements.

- [ ] **SIP-01 · P2 · Runner · Integrated SIP scenarios.** Promote selected
  sipexer/SIPPTS/SIPp workflows into versioned adapters for OPTIONS, registration,
  call setup and teardown with exact WS/WSS path/subprotocol and separate SIP
  credentials. Retain transaction/dialog transcripts and positive controls.
  An open WebSocket and successful OPTIONS response do not establish SIP auth.

- [ ] **SIP-02 · P2 · Runner + Paired · SIP authorization and dialog attacks.**
  Test registration overwrite/removal, Contact manipulation, caller identity
  spoofing, forged BYE/CANCEL/re-INVITE/REFER and replay against owned dialogs.
  Check CSeq/Call-ID/tag/route handling, method authorization and cross-extension
  isolation. Done when a forbidden registration or dialog effect is demonstrated
  and registrations/calls are cleaned up.

- [ ] **SIP-03 · P2 · Runner + Paired · Digest and enumeration.** Add bounded
  account-enumeration controls, nonce/replay/algorithm checks and credential-leak
  scenarios against controlled accounts. Separate password-strength testing from
  the standard profile. Confirm challenge-bound digest disclosure rather than
  labelling any Authorization header a leak.
  [Enable Security's SIP Digest Leak research](https://resources.enablesecurity.com/resources/sipdigestleak-tut.pdf).

- [ ] **SIP-04 · P2 · Paired · WebRTC-to-telephony policy.** Test encryption
  termination/downgrade on gateway legs, unauthorized call transfer/routing,
  DTMF/control access and declared dial-plan restrictions using test destinations.
  Correlate signaling and media; report toll-fraud exposure only from a demonstrated
  forbidden route, without requiring a chargeable real call.

## Resource exhaustion and resilience

- [ ] **RES-01 · P2 · Burp + Paired · Actual signaling/API rate tests.** Add
  measured join/create-room/token issuance, WS connection/message, renegotiation,
  ICE-restart and reconnect scenarios. Observe server requests, throttling,
  per-account/tenant effects, a healthy control call and recovery. Keep these
  separate from T8's local loop; a successful bounded run does not establish
  resistance to larger loads.

- [ ] **RES-02 · P2 · Runner + Lab · Protocol/resource budgets.** Coordinate
  TURN allocation churn, incomplete DTLS handshakes, candidate floods, repeated
  subscriptions, DataChannel buffering and RTP/RTCP/feedback bursts. Fix packet,
  byte, duration and concurrency ceilings; monitor available server resource
  metrics and call quality. Stop on defined health thresholds and verify recovery
  and cleanup. Do not infer server CPU/memory use solely from client latency.

- [ ] **RES-03 · P2 · Paired · Isolation under failure.** Induce selected test
  peer loss, TURN expiry, renegotiation failure, slow consumers and backend
  reconnection; verify one tenant/room cannot disrupt another. Measure call setup,
  stalls, packet loss and time to recover against baseline. Record fault-injection
  location so ordinary network failure is not misreported as an application DoS.

## Native fuzzing, labs, and dependable delivery

- [ ] **LAB-01 · P3 · Lab · Native parser/decoder integration.** Support
  isolated instrumented builds for SDP, RTP/RTCP, STUN/TURN, DTLS, SCTP and relevant
  audio/video decoders. Import coverage, sanitizer stacks, seeds, minimized cases
  and build IDs; replay only on matching lab builds. M3+ tests JavaScript-reachable
  parsing and cannot substitute for this. [Original WebRTC RCE research](https://margin.re/2024/07/you-cant-spell-webrtc-without-rce-part-1/).

- [ ] **LAB-02 · P3 · Lab · Encoded-frame fuzzing.** Add a media-delivery and
  reproduction adapter for [H26Forge](https://github.com/h26forge/h26forge), then
  applicable VP8/VP9/AV1/Opus harnesses as available. Distinguish malformed SDP
  codec parameters from malformed compressed frames reaching a decoder. Require
  receiver crash/hang/sanitizer evidence; codec enumeration does not imply fuzz
  coverage or an exploitable decoder.

- [ ] **LAB-03 · P1 · Lab · Known-good/known-bad regression environments.**
  Pin [DVRTC](https://github.com/EnableSecurity/DVRTC) and
  [RTC_Attacks](https://github.com/WebRTC-Thesis-Unina/RTC_Attacks) scenarios plus
  a maintained minimal app, TURN server, WS service and SFU. Pair vulnerable
  fixtures with corrected controls. Validate auth, forwarding, room isolation,
  consent and packet integrity outcomes; do not assume either lab covers every
  case. Each test pack needs reproducible expected evidence.

- [ ] **LAB-04 · P1 · Runner · Evolve the external catalogue.** Existing
  stunner, TURNado, TURNt, coturn, SIPPTS, SIPVicious, sipexer, Nmap, testssl and
  TShark recipes stay useful. First add result import and execution adapters for
  non-overlapping capabilities; then evaluate PLAN E1–E6. Group by app/endpoint,
  show provenance/scope/credential age, and use unique artifact paths. A tool's
  presence or successful process exit must never mark unexecuted modules covered.

- [x] **LAB-05 · P0 · Extension and runner self-protection.** Test bridge
  origin/Host/session authorization, cross-page command isolation, DNS rebinding,
  malformed telemetry, bounded decompression/parsing, untrusted report content,
  CSV/spreadsheet injection and runner argument handling. Preserve credential
  values losslessly while using format-safe rendering; do not introduce masking.
  Fuzzed target data must not become shell commands, report scripts, or actions
  against another engagement.
  *(Shipped in 1.1.0: `BridgeSessions.kt` tokens, Host/Origin validation, bounded JSON, formula-safe CSV rendering).*

- [x] **LAB-06 · P1 · Regression, packaging, and report completion.** Every new
  test needs meaningful positive/negative fixtures, scope-revocation and cleanup
  checks where relevant, event registration in `EventTypes.KNOWN` and
  `BridgeServer.summarize`, and Run All/M7 coverage. Add machine-readable result
  export, replayable scenarios and before/after remediation comparison. For a
  functional release, align extension metadata and agent `AGENT_VERSION`, document
  runner prerequisites and page reloads, and verify the packaged artifact.
  *(Shipped in 1.1.0: Full regression suite, version alignment at 1.1.0, packaged JAR).*

## Research-to-test mapping and remaining boundaries

| Primary resource | Useful contribution | Backlog |
| --- | --- | --- |
| [awesome-rtc-hacking](https://github.com/EnableSecurity/awesome-rtc-hacking/blob/main/README.md) | RTC research/tool/lab discovery across multiple layers | Whole backlog; LAB-03/04 |
| [stunner](https://github.com/firefart/stunner), [TURNado](https://github.com/SySS-Research/TURNado) | TURN protocol, destination and transfer capabilities to adapt | TRN-01–08 |
| [TURNt](https://github.com/praetorian-inc/turnt) | Controlled relay/tunnel verification; forwarding is not automatically an auth bug | TRN-04/05, LAB-04 |
| [Project Zero call-state study](https://projectzero.google/2021/01/the-state-of-state-machines.html) | Consent and state transitions can fail despite encrypted transport | SIG-07 |
| [DTLS race research](https://www.enablesecurity.com/blog/novel-dos-vulnerability-affecting-webrtc-media-servers/) | ICE/DTLS sequencing and call-setup resilience | DTL-04 |
| [CVE-2022-0778 RTC reproduction](https://www.enablesecurity.com/blog/exploiting-cve-2022-0778-in-openssl-vs-webrtc-platforms/) | Reachability and library/build prerequisites matter | DTL-05 |
| [coturn ACL advisory](https://github.com/coturn/coturn/security/advisories/GHSA-2x4g-wx24-48m4) | IPv6 translation/policy cases require actual route evidence; not intrinsic coturn RCE | TRN-04 |
| [coturn integrity advisory](https://github.com/coturn/coturn/security/advisories/GHSA-5538-7cxj-5jcc) | Authenticated message semantics and integrity boundaries | TRN-06 |
| [coturn buffer disclosure advisory](https://github.com/coturn/coturn/security/advisories/GHSA-c8r8-8vp5-6gcm) | Padding/response initialization regression fixture | TRN-06, LAB-01 |
| [WebRTC security study](https://webrtc-security.github.io/) | Historical taxonomy; use current standards and behavior for verdicts | COR, ICE, DTL, SFU |
| [LiveKit token lifecycle](https://docs.livekit.io/frontends/reference/tokens-grants/), [Janus admin API](https://janus.conf.meetecho.com/docs/admin.html) | Concrete deployment-specific grant and management surfaces | SIG-05, SFU, APP-01 |

The standards and source links beside individual tasks are the implementation
references; recheck the deployed version, current advisory details and tool CLI
when implementing. The existing ten-tool catalogue is already documented, so
adding its names again is not the primary expansion work.

SS7, Diameter, GTP, VoLTE carrier attacks, handset firmware, and voice-VLAN
hopping from the broader RTC list should remain separate packs unless an actual
WebRTC integration exposes that boundary. Unattended account creation, arbitrary
provider credential harvesting, and general-purpose tunneling infrastructure are
not necessary to verify a selected relay's policy. Storage residency, compliance
and inaccessible server configuration require supplied evidence or manual review;
keep them visible as such. Native zero-day discovery remains a lab research
capability rather than a promised outcome of Run All.

## Validation when implementing this backlog

Choose checks appropriate to the feature and run the required existing suites.
Do not convert this documentation review into a live target scan.

```powershell
cmd.exe /c "gradlew.bat test --offline --console=plain --no-daemon"
node --test agent/webrtc-agent.test.cjs agent/active-tests.test.cjs
python -m unittest discover -s runner -p 'test_*.py'
cmd.exe /c "gradlew.bat shadowJar --offline --console=plain --no-daemon"
```

Drop `--offline` only when a new dependency needs resolution. New protocol packs
also need controlled integration runs proving the vulnerable case, corrected
case, missing prerequisite, timeout, cancellation and scope loss. A source review
or generated command is never equivalent to those executions.
