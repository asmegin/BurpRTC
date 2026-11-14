# BurpRTC — WebRTC Security Testing Suite for Burp Suite

**One-line summary:** Client-agnostic WebRTC security testing suite for Burp Suite that instruments browser calls, audits SDP/ICE/DTLS/SRTP and STUN/TURN infrastructure, tests signaling and DataChannel access control, and reports WebRTC vulnerabilities.

A client-agnostic Burp Suite extension that drives a WebRTC penetration test from a single **BurpRTC** Suite tab. Nothing target-specific is compiled in — every engagement detail is configuration, persisted in the Burp project file.

> **Authorized testing only.** Every active action (injection, mutation, fuzzing,
> ICE probing, replay) is gated on Burp **Target scope**, the host allow-list and
> the agent switch. Credentials are never masked.

**Version 1.3.2** · JDK 21 · Burp Montoya API 2026.7 · self-contained (no Python needed)

## What it does

An injected browser agent hooks the W3C WebRTC APIs, and Burp handlers observe and
replay HTTP(S) and WebSocket signaling:

- **Passive evidence** — SDP, ICE (IP privacy), DTLS/SRTP, certificates and
  fingerprint binding, DataChannels, getStats, signaling, and the **original**
  response headers captured before injection (CSP, framing, Permissions-Policy,
  HSTS, cookies).
- **Browser checks** — camera, microphone and screen-share lifecycle (including
  capture left on after hang-up), permission states, device-label exposure, and
  cross-window `postMessage` listeners.
- **XSS canaries** — self-reporting payloads for chat, display names and file
  names. Execution in any instrumented page (for example an advisor console) is
  proven by the page itself; Burp Collaborator covers uninstrumented pages and
  callback URLs. Also available as an Intruder payload source.
- **Access control** — captured sessions with **customer / advisor roles**; a
  lower role or another customer receiving the owner's data is reported as a
  likely violation, with a credential-free control to rule out public resources.
- **Meeting links** — invite-token guessability, altered / removed token and
  no-session replays, and a recheck after the meeting for link reuse.
- **Documents & recordings** — downloads replayed across sessions, without
  credentials and with neighbouring IDs; signed-link lifetime review.
- **Active browser modules** — SDP mutation and parser fuzzing, DataChannel fuzz,
  STUN/TURN gathering and a local negotiation loop.
- **DataChannel runner** — paired-session tests for RTCDataChannel and Jitsi
  Colibri bridge channels. It covers channel discovery, version-aware message
  fuzzing, binary and size boundaries, authorization and room isolation, replay
  and call lifecycle, bounded load and churn, and a comparison with the Colibri
  WebSocket transport.
  - Each case is verified at the recipients and classified PASS / FAIL /
    INCONCLUSIVE / BLOCKED / NOT APPLICABLE, and mapped in a coverage report.
  - An integrated browser runner launches the customer, advisor and test-room
    sessions and drives the app's call controls.
  - Message fuzzing uses automatic payloads by default; you can add your own
    payload list or file, or use only your own.
  - FAIL results become specific entries in Burp's Issues list.
  - Native SCTP packet fuzzing needs a separate test peer.
- **Security checks** — built-in STUN/TURN tests (credential matrix, real relay
  forwarding via a second allocation, channel paths, refresh/release) and saved
  HTTP/WebSocket scenarios sent through Burp.
- **TLS tests** — built-in JVM scanner for HTTPS/WSS and TURN-over-TLS (SSL 3.0 to
  TLS 1.3, TLS 1.2 cipher suites, certificate); SSLyze remains optional.
- **Report & Burp issues** — a checklist plus twelve evidence sections, and
  deduplicated WebRTC findings in Burp's own Issues list.
- **Video banking preset** — one click selects every scan and shows an
  advisor / customer test checklist.

## Build from source

Requires JDK 21 (the Gradle wrapper handles the rest):

```
cmd.exe /c ".\gradlew.bat shadowJar --offline --console=plain --no-daemon"
```

Output: `build/libs/burprtc-all.jar`.

## Load in Burp

1. Extensions → Installed → Add → extension type **Java** → select `build/libs/burprtc-all.jar`.
2. Output shows `BurpRTC v1.3.2 loaded`; a **BurpRTC** tab appears.
3. In **Setup**: enable agent injection and add the app host(s) to the allow-list.
4. Add the target to Burp **Target scope**, browse the app through Burp and join a
   call. In **Scan All**, pick a preset (or a subset of scans) and click
   **Scan selected**. Reload browser pages after updating the extension so they
   pick up agent 1.3.2.

## Design boundary

This reaches the signaling- and API-visible surface, the browser, STUN/TURN and
TLS-over-TCP listeners. Raw media (RTP/RTCP/SRTP), media DTLS over UDP and native
parser fuzzing are delegated to external tooling (see the External commands tab).
A replay result or generated command is a lead to investigate unless the evidence
says otherwise.

## Documentation

Full reference — every module, release history, the coverage roadmap and the
external-tool catalogue — is in **[DOCS.md](DOCS.md)**.

## License

[Apache 2.0](LICENSE).

The optional SSLyze engine installs [SSLyze](https://github.com/nabla-c0d3/sslyze)
(AGPLv3) and its dependencies into a separate Python environment; their code is not
included in the extension JAR.
