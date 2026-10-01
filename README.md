# WebRTC Test Suite — Burp Suite extension

A client-agnostic Burp Suite Professional extension that drives a WebRTC
penetration test from a single Suite tab. Nothing target-specific is compiled
in — every engagement detail is configuration, persisted in the Burp project file.

> **Authorized testing only.** Every active action (injection, mutation, fuzzing,
> ICE probing, replay, flood) is gated on Burp **Target scope**. Credentials live
> only in the Burp project file and are never masked.

**Version 1.0.1** · JDK 21 · Burp Montoya API 2026.7

## What it does

It injects a browser agent that hooks the W3C WebRTC JavaScript API (SDP, ICE,
DataChannel) and observes/rewrites HTTP(S), giving you the signaling- and
API-visible attack surface from inside Burp:

- **Passive telemetry (M1/M2)** — SDP, ICE candidates (private-IP flagged),
  DTLS/SRTP ciphers, DataChannels, deep `getStats`, and DTLS certificate /
  fingerprint binding.
- **Guided Run All** — one click: config check → telemetry review → live checks,
  with plain-English findings (weak/absent media crypto, cleartext SDES keys,
  public-IP disclosure, codec enumeration, guessable IDs, TURN relay allocation).
- **Active modules** — SDP mutation (M3), SDP parser fuzz (M3+), DataChannel fuzz
  (M4), authz/IDOR matrix (M5), STUN/TURN gather (M6), opt-in signaling flood (T8).
- **External Tests** — generates ready-to-copy Linux/Bash commands for ten
  external RTC tools (text only; it never executes them).
- **Findings (M7)** — exports a Markdown report and CSV, with credentials intact.

Version 1.0.1 fixes embedded video pages being blocked by `X-Frame-Options:
SAMEORIGIN` after CSP stripping. The injector now preserves enforced
`frame-ancestors` directives while relaxing the remaining CSP restrictions.

## Download

Prebuilt extension (bundles the browser agent):
**[`dist/webrtc-testsuite-all.jar`](dist/webrtc-testsuite-all.jar)**.

## Build from source

Requires JDK 21 (the Gradle wrapper handles the rest):

```
gradlew.bat shadowJar --console=plain --no-daemon
```

Output: `build/libs/webrtc-testsuite-all.jar`.

## Load in Burp

1. Extensions → Installed → Add → extension type **Java** → select the jar.
2. Output shows `WebRTC Test Suite v1.0.1 loaded`; a **WebRTC** tab appears.
3. In **Config (M0)**: enable agent injection, add the app host(s) to the
   allow-list, Save. Advanced settings are auto-configured — leave them collapsed.
4. Add the target to Burp **Target scope**, browse the app through Burp, join a
   call — telemetry fills in, and **Run All** ties the modules together.

## Design boundary

This reaches the **signaling- and API-visible** surface only. The media plane
(RTP/RTCP/SRTP) and native-parser memory-safety fuzzing are out of scope by
construction and delegated to external tooling (see the External Tests tab). API
acceptance or a generated command is a lead to investigate, never a confirmed
vulnerability.

## Documentation

Full reference — every module, the coverage roadmap, the external-tool catalogue
and detailed usage — is in **[DOCS.md](DOCS.md)**.

## License

[Apache 2.0](LICENSE).
