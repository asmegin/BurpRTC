/*
 * WebRTC Test Suite — generic browser agent (client-agnostic).
 * Hooks the standard W3C WebRTC API so it works on any WebRTC app regardless
 * of framework or signaling. Injected into the top page and every iframe by the
 * Burp extension's M1 injector. Config arrives via window.__WRTC_CFG__.
 * Versioned independently of the extension.
 */
(function () {
  "use strict";
  if (window.__WRTC_AGENT_ACTIVE__) return;
  window.__WRTC_AGENT_ACTIVE__ = true;

  var CFG = window.__WRTC_CFG__ || {};
  var COLLECT = CFG.collect;
  var COMMAND = CFG.command;
  var FRAME = (function () { try { return location.href; } catch (e) { return "frame"; } })();
  var AGENT_VERSION = "1.0.5";
  var AGENT_ID = "agent-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  var NativePeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
  var channels = new Map();
  var wrappedChannels = new WeakSet();
  var channelSeq = 0;
  var seenCommands = new Set();
  var completedCommands = [];
  var activeCommand = null;
  var unloading = false;
  var mutationSeq = 0;
  var mutationStatus = "";
  var latestObservedOffer = "";
  var latestObservedAnswer = "";
  var statsSamples = new WeakMap();
  // Application peers, so a manual stats capture can find a live connection.
  var peersSeen = [];
  // Bounded automatic stats sampling: a short burst right after connect, then a
  // slower steady interval, capped per connection so long calls cannot flood.
  var STATS_MAX = 20, STATS_BURST = 5, STATS_INTERVAL_MS = 5000;

  var PRIVATE_RE = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|fe80:[0-9a-f:]+|f[cd][0-9a-f]{2}:[0-9a-f:]+)/i;

  function isPrivate(text) {
    try { return PRIVATE_RE.test(String(text)); } catch (e) { return false; }
  }

  function beacon(event) {
    if (!COLLECT) return;
    try {
      event.frame = location.href || FRAME;
      event.agent = AGENT_ID;
      var body = JSON.stringify(event);
      return fetch(COLLECT, { method: "POST", body: body, mode: "no-cors", keepalive: body.length < 8000 })
        .catch(function () {});
    } catch (e) { /* never break the app */ }
  }

  var pcSeq = 0;
  // ICE server configurations observed on created peers, including TURN account
  // credentials. The tester controls evidence; nothing is masked or dropped here.
  var observedIceServers = [];

  function recordIceServers(cfg) {
    if (!cfg || !cfg.iceServers) return;
    for (var i = 0; i < cfg.iceServers.length; i++) {
      var s = cfg.iceServers[i];
      if (!s) continue;
      var entry = { urls: s.urls, username: s.username, credential: s.credential, credentialType: s.credentialType };
      var key = safeJson(entry);
      var seen = false;
      for (var j = 0; j < observedIceServers.length; j++) {
        if (safeJson(observedIceServers[j]) === key) { seen = true; break; }
      }
      if (!seen) observedIceServers.push(entry);
    }
  }

  function wrapPeerConnection() {
    var Native = NativePeerConnection;
    if (!Native) return;

    function Wrapped(cfg, constraints) {
      var pc = new Native(cfg, constraints);
      var pcId = "pc" + (++pcSeq);
      peersSeen.push({ pc: pc, pcId: pcId });
      if (peersSeen.length > 32) peersSeen.shift();
      // Preserve the full ICE configuration, including TURN usernames/credentials:
      // the tester decides what to remove from screenshots and report evidence.
      recordIceServers(cfg);
      beacon({ type: "pc-new", pc: pcId, detail: safeJson({
        iceServers: cfg && cfg.iceServers ? cfg.iceServers.map(function (s) {
          return { urls: s.urls, username: s.username, credential: s.credential, credentialType: s.credentialType };
        }) : [],
        iceTransportPolicy: cfg && cfg.iceTransportPolicy
      }) });

      pc.addEventListener("icecandidate", function (e) {
        if (e && e.candidate && e.candidate.candidate) {
          var cand = e.candidate.candidate;
          beacon({ type: "ice", pc: pcId, candidate: cand, private: isPrivate(cand) });
        }
      });

      // ICE can connect before DTLS. Sample again after the full connection
      // connects and keep sampling at a slow, bounded interval while connected.
      var statsTimer = null, statsLeft = 0, statsTaken = 0;
      function sampleStats() {
        statsTimer = null;
        if (unloading || pc.connectionState === "closed" || pc.signalingState === "closed") return;
        reportStats(pc, pcId);
        statsTaken++; statsLeft--;
        if (statsLeft > 0) statsTimer = setTimeout(sampleStats, statsTaken < STATS_BURST ? 1000 : STATS_INTERVAL_MS);
      }
      function connectionChanged() {
        var snapshot = peerState(pc);
        snapshot.type = "pc-state"; snapshot.pc = pcId;
        snapshot.detail = "peer=" + snapshot.connectionState + " ICE=" + snapshot.iceConnectionState +
          " signaling=" + snapshot.signalingState + " SCTP=" + snapshot.sctpState;
        beacon(snapshot);
        if (pc.connectionState === "closed" || pc.signalingState === "closed") {
          clearTimeout(statsTimer); statsTimer = null; statsLeft = 0; return;
        }
        if (pc.connectionState === "connected" || pc.iceConnectionState === "connected" || pc.iceConnectionState === "completed") {
          if (statsLeft <= 0) { statsLeft = STATS_MAX; statsTaken = 0; sampleStats(); }
        }
      }
      pc.addEventListener("iceconnectionstatechange", connectionChanged);
      pc.addEventListener("connectionstatechange", connectionChanged);
      pc.addEventListener("signalingstatechange", connectionChanged);
      var origClose = pc.close;
      if (typeof origClose === "function") pc.close = function () {
        var result = origClose.apply(pc, arguments);
        var event = peerState(pc);
        event.type = "pc-state"; event.pc = pcId; event.action = "close-called";
        event.detail = "RTCPeerConnection.close() called by page";
        event.stack = String(new Error().stack || "").slice(0, 2048);
        beacon(event);
        return result;
      };

      pc.addEventListener("datachannel", function (e) {
        if (e && e.channel) wrapDataChannel(e.channel, pcId, "remote", pc);
      });

      hookSdp(pc, pcId);
      hookCreateDataChannel(pc, pcId);
      return pc;
    }

    Wrapped.prototype = Native.prototype;
    Object.setPrototypeOf(Wrapped, Native);
    try {
      window.RTCPeerConnection = Wrapped;
      if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = Wrapped;
    } catch (e) {}
  }

  function hookSdp(pc, pcId) {
    // Keep delayed SDP operations and trickled candidates in application call order.
    var pending = Promise.resolve();
    var lastLocalMutation = null;
    function enqueue(action) {
      var result = pending.then(action);
      pending = result.catch(function () {});
      return result;
    }

    function resultEvent(method, mutation, error) {
      beacon({ type: error ? "sdp-error" : "sdp-result", pc: pcId,
        mutationId: mutation ? mutation.id : "", method: method,
        detail: method + (error ? " rejected: " + error.name + ": " + error.message : " accepted"),
        accepted: !error });
    }

    function observe(method, result, mutation) {
      return Promise.resolve(result).then(function (value) {
        if (mutation) resultEvent(method, mutation, null);
        return value;
      }, function (error) {
        resultEvent(method, mutation, error);
        throw error;
      });
    }

    ["createOffer", "createAnswer"].forEach(function (m) {
      var orig = pc[m];
      if (typeof orig !== "function") return;
      pc[m] = function () {
        // Legacy callback overloads are left intact; M3 targets promise APIs.
        if (typeof arguments[0] === "function") return orig.apply(pc, arguments);
        var args = arguments;
        return enqueue(function () {
          return Promise.resolve(orig.apply(pc, args)).then(function (desc) {
            return mutateDescription(desc, "local", m, pcId).then(function (change) {
              lastLocalMutation = change.id ? change : null;
              var out = change.description;
              if (out && out.sdp) { rememberSdp(out); beacon({ type: "sdp-local", pc: pcId, kind: out.type, sdp: out.sdp, private: isPrivate(out.sdp) }); }
              return out;
            });
          });
        });
      };
    });
    ["setLocalDescription", "setRemoteDescription", "addIceCandidate"].forEach(function (m) {
      var orig = pc[m];
      if (typeof orig !== "function") return;
      pc[m] = function () {
        if (typeof arguments[1] === "function" || typeof arguments[2] === "function") return orig.apply(pc, arguments);
        var args = Array.prototype.slice.call(arguments);
        return enqueue(function () {
          if (m !== "setRemoteDescription") {
            var mutation = m === "setLocalDescription" && args[0] && lastLocalMutation &&
              args[0].sdp === lastLocalMutation.description.sdp ? lastLocalMutation : null;
            return observe(m, Promise.resolve().then(function () { return orig.apply(pc, args); }), mutation);
          }
          return mutateDescription(args[0], "remote", m, pcId).then(function (change) {
            if (args.length) args[0] = change.description;
            var desc = change.description;
            if (desc && desc.sdp) { rememberSdp(desc); beacon({ type: "sdp-remote", pc: pcId, kind: desc.type, sdp: desc.sdp, private: isPrivate(desc.sdp) }); }
            return observe(m, Promise.resolve().then(function () { return orig.apply(pc, args); }), change.id ? change : null);
          });
        });
      };
    });
  }

  function requestBridge(extra) {
    if (!COMMAND) return Promise.resolve(null);
    // No cached authorization: scope, host allow-list and enable flags are checked each time.
    var frame;
    try { frame = location.href; } catch (e) { return Promise.resolve(null); }
    var controller = new AbortController();
    var timer;
    var timeout = new Promise(function (_, reject) {
      timer = setTimeout(function () { controller.abort(); reject(new Error("bridge timeout")); }, 1500);
    });
    var query = "frame=" + encodeURIComponent(frame) + "&agent=" + encodeURIComponent(AGENT_ID);
    Object.keys(extra || {}).forEach(function (key) { query += "&" + encodeURIComponent(key) + "=" + encodeURIComponent(extra[key]); });
    var request = fetch(COMMAND + (COMMAND.indexOf("?") < 0 ? "?" : "&") + query,
      { method: "GET", cache: "no-store", signal: controller.signal })
      .then(function (r) { if (!r.ok) throw new Error("bridge HTTP " + r.status); return r.json(); });
    return Promise.race([request, timeout]).catch(function () { return null; })
      .then(function (doc) { clearTimeout(timer); return doc; });
  }

  function readMutationSettings() {
    return requestBridge().then(function (doc) {
      if (!doc) { announceMutationStatus("bridge unavailable; SDP unchanged"); return null; }
      var command = (Array.isArray(doc.commands) ? doc.commands : []).find(function (c) { return c.type === "sdp-mutation"; });
      var cfg = command && command.config;
      var active = cfg && cfg.enabled === true;
      announceMutationStatus(active ? "enabled: " + cfg.target : "disabled or page outside scope");
      return active ? cfg : null;
    });
  }

  function announceMutationStatus(detail) {
    if (detail === mutationStatus) return;
    mutationStatus = detail;
    beacon({ type: "sdp-mutation-status", detail: detail });
  }

  function applySdpRules(sdp, cfg) {
    if (sdp.length > 262144) throw new Error("SDP exceeds 256 KiB character limit");
    var newline = sdp.indexOf("\r\n") >= 0 ? "\r\n" : "\n";
    var trailing = /\r?\n$/.test(sdp);
    var lines = sdp.split(/\r?\n/);
    if (trailing) lines.pop();
    lines = lines.filter(function (line) {
      if (cfg.removeFingerprint && line.indexOf("a=fingerprint:") === 0) return false;
      if (cfg.removeCandidates && (line.indexOf("a=candidate:") === 0 || line === "a=end-of-candidates")) return false;
      return true;
    });
    if (["sendrecv", "sendonly", "recvonly", "inactive"].indexOf(cfg.mediaDirection) >= 0) {
      var output = [], section = [];
      function flush() {
        if (/^m=(audio|video) /.test(section[0] || "")) {
          section = section.filter(function (line) { return !/^a=(sendrecv|sendonly|recvonly|inactive)$/.test(line); });
          section.push("a=" + cfg.mediaDirection);
        }
        output = output.concat(section);
        section = [];
      }
      lines.forEach(function (line) { if (line.indexOf("m=") === 0) flush(); section.push(line); });
      flush();
      lines = output;
    }
    var out = lines.join(newline) + (trailing ? newline : "");
    var rules = Array.isArray(cfg.rules) ? cfg.rules :
      (typeof cfg.find === "string" && cfg.find.length ? [{ find: cfg.find, replacement: cfg.replacement || "" }] : []);
    for (var ruleIndex = 0; ruleIndex < rules.length; ruleIndex++) {
      var rule = rules[ruleIndex] || {};
      if (typeof rule.find !== "string" || !rule.find.length) continue;
      // Normalize line endings and replace literal substrings, not just whole SDP lines.
      var find = rule.find.replace(/\r?\n/g, newline);
      var replacement = String(rule.replacement || "").replace(/\r?\n/g, newline);
      var position = 0, projected = out.length;
      while ((position = out.indexOf(find, position)) >= 0) {
        projected += replacement.length - find.length;
        if (projected > 262144) throw new Error("mutated SDP exceeds 256 KiB character limit");
        position += find.length;
      }
      out = out.split(find).join(replacement);
    }
    if (out.length > 262144) throw new Error("mutated SDP exceeds 256 KiB character limit");
    return out;
  }

  function mutateDescription(desc, stage, method, pcId) {
    if (!desc || typeof desc.sdp !== "string" || !desc.sdp || desc.type === "rollback") {
      return Promise.resolve({ description: desc });
    }
    return readMutationSettings().then(function (cfg) {
      if (!cfg || (cfg.target !== stage && cfg.target !== "both") || (cfg.pcId && cfg.pcId !== pcId)) {
        return { description: desc };
      }
      try {
        var changed = applySdpRules(desc.sdp, cfg);
        if (changed === desc.sdp) return { description: desc };
        var id = pcId + "-m" + (++mutationSeq);
        beacon({ type: "sdp-mutation", pc: pcId, mutationId: id, stage: stage, method: method, kind: desc.type,
          detail: id + " " + method + " " + desc.sdp.length + " -> " + changed.length + " chars",
          before: desc.sdp.slice(0, 65536), after: changed.slice(0, 65536),
          truncated: desc.sdp.length > 65536 || changed.length > 65536,
          private: isPrivate(desc.sdp) || isPrivate(changed) });
        return { id: id, description: { type: desc.type, sdp: changed } };
      } catch (e) {
        beacon({ type: "sdp-error", pc: pcId, method: method, detail: "Mutation skipped: " + e.message });
        return { description: desc };
      }
    });
  }

  function hookCreateDataChannel(pc, pcId) {
    var orig = pc.createDataChannel;
    if (typeof orig !== "function") return;
    pc.createDataChannel = function () {
      var dc = orig.apply(pc, arguments);
      wrapDataChannel(dc, pcId, "local", pc);
      return dc;
    };
  }

  function wrapDataChannel(dc, pcId, origin, pc) {
    try {
      if (wrappedChannels.has(dc)) return;
      wrappedChannels.add(dc);
      var channelId = "dc" + (++channelSeq);
      var createdAt = Date.now(), everOpened = dc.readyState === "open", autoRequested = false;
      channels.set(channelId, { dc: dc, pc: pc, pcId: pcId });
      beacon({ type: "dc-created", pc: pcId, channelId: channelId, label: dc.label, detail: origin, state: dc.readyState });
      function diagnostic(detail, action, error) {
        var event = peerState(pc);
        event.type = "dc-state"; event.pc = pcId; event.channelId = channelId; event.label = dc.label;
        event.state = dc.readyState; event.everOpened = everOpened; event.elapsedMs = Date.now() - createdAt;
        event.detail = detail;
        if (action) { event.action = action; event.stack = String(new Error().stack || "").slice(0, 2048); }
        if (error) {
          event.error = cleanError(error); event.errorDetail = error.errorDetail;
          event.sctpCauseCode = error.sctpCauseCode;
        }
        beacon(event);
      }
      function state() {
        if (dc.readyState === "open") everOpened = true;
        diagnostic(dc.readyState + (dc.readyState === "closed" && !everOpened ? " before reaching open" : ""));
        if (dc.readyState === "closed") channels.delete(channelId);
        return heartbeat();
      }
      function opened() {
        var observed = state();
        if (autoRequested || dc.readyState !== "open") return;
        autoRequested = true;
        // The heartbeat must reach Burp before the fresh, scope-gated open request.
        Promise.resolve(observed).then(function () {
          if (unloading || dc.readyState !== "open" || activeCommand) return null;
          return requestBridge({ autoFuzz: channelId });
        }).then(function (doc) {
          if (!doc || !Array.isArray(doc.commands)) return;
          doc.commands.filter(function (c) { return c.type === "dc-fuzz" && c.channelId === channelId; }).forEach(dispatchCommand);
        }).catch(function () {});
      }
      dc.addEventListener("open", opened);
      dc.addEventListener("close", state);
      dc.addEventListener("error", function (e) { diagnostic("channel error" + (e && e.error ? ": " + cleanError(e.error) : ""), null, e && e.error); });
      var origClose = dc.close;
      if (typeof origClose === "function") dc.close = function () {
        var result = origClose.apply(dc, arguments);
        diagnostic("RTCDataChannel.close() called by page", "close-called");
        return result;
      };
      var origSend = dc.send;
      dc.send = function (data) {
        var result = origSend.apply(dc, arguments);
        beacon({ type: "dc-send", pc: pcId, channelId: channelId, label: dc.label, bytes: sizeOf(data) });
        return result;
      };
      dc.addEventListener("message", function (e) {
        beacon({ type: "dc-recv", pc: pcId, channelId: channelId, label: dc.label, bytes: sizeOf(e && e.data),
          preview: typeof (e && e.data) === "string" ? e.data.slice(0, 512) : "[binary]" });
      });
      if (dc.readyState === "open") opened();
      else if (dc.readyState === "closed") state();
      else heartbeat();
    } catch (e) {}
  }

  function peerState(pc) {
    return { connectionState: pc.connectionState || "unknown", iceConnectionState: pc.iceConnectionState || "unknown",
      signalingState: pc.signalingState || "unknown", sctpState: pc.sctp && pc.sctp.state || "unknown" };
  }

  function rememberSdp(desc) {
    if (desc.type === "offer") latestObservedOffer = desc.sdp;
    if (desc.type === "answer") latestObservedAnswer = desc.sdp;
  }

  function statNumber(value) {
    if (typeof value === "number" && isFinite(value)) return value;
    if (typeof value === "string" && value !== "" && isFinite(Number(value))) return Number(value);
    return null;
  }

  // One bounded getStats() snapshot: the transport/DTLS roles, the chosen ICE
  // pair and every candidate, in-use RTP streams (packet counts, loss, jitter),
  // and certificate fingerprints. Certificates are emitted once each as a
  // separate dtls-cert event carrying the DER bytes; the snapshot only references
  // their fingerprint so a long call cannot accumulate large repeated payloads.
  function reportStats(pc, pcId) {
    if (!pc.getStats) return Promise.resolve();
    return pc.getStats(null).then(function (report) {
      var stats = [];
      report.forEach(function (s) { stats.push(s); });
      var previous = statsSamples.get(pc) || {};
      statsSamples.set(pc, previous);

      var transport = null, certs = {}, codecs = {}, candidates = {}, selectedPair = null;
      stats.forEach(function (s) {
        if (s.type === "transport" && !transport) transport = s;
        else if (s.type === "certificate") certs[s.id] = s;
        else if (s.type === "codec") codecs[s.id] = s;
        else if (s.type === "local-candidate" || s.type === "remote-candidate") candidates[s.id] = s;
        else if (s.type === "candidate-pair" && (s.selected || s.nominated) && s.state === "succeeded") selectedPair = s;
      });

      if (transport) {
        var detail = "dtls=" + (transport.dtlsCipher || "?") + " srtp=" + (transport.srtpCipher || "?") + " tls=" + (transport.tlsVersion || "?");
        var signature = detail + " state=" + (transport.dtlsState || "?");
        if (previous[transport.id] !== signature) {
          previous[transport.id] = signature;
          beacon({ type: "crypto", pc: pcId, transportId: transport.id, dtlsState: transport.dtlsState || "unknown", detail: detail });
        }
      }

      var rtp = [];
      stats.forEach(function (s) {
        if (s.type !== "outbound-rtp" && s.type !== "inbound-rtp") return;
        if (s.isRemote === true) return;
        var outbound = s.type === "outbound-rtp";
        var codec = "";
        if (s.codecId && codecs[s.codecId] && codecs[s.codecId].mimeType) codec = codecs[s.codecId].mimeType;
        else if (s.mimeType) codec = s.mimeType;
        rtp.push({
          direction: outbound ? "outbound" : "inbound",
          kind: s.kind || s.mediaType || "",
          ssrc: s.ssrc != null ? String(s.ssrc) : "",
          payloadType: statNumber(s.payloadType),
          packets: statNumber(outbound ? s.packetsSent : s.packetsReceived),
          bytes: statNumber(outbound ? s.bytesSent : s.bytesReceived),
          packetsLost: statNumber(s.packetsLost),
          jitter: typeof s.jitter === "number" ? s.jitter : null,
          nackCount: statNumber(s.nackCount),
          pliCount: statNumber(s.pliCount),
          firCount: statNumber(s.firCount),
          codec: codec
        });
      });

      var candidateStats = [];
      stats.forEach(function (s) {
        if (s.type !== "local-candidate" && s.type !== "remote-candidate") return;
        candidateStats.push({
          role: s.type === "local-candidate" ? "local" : "remote",
          type: s.candidateType || "",
          protocol: s.protocol || "",
          address: s.address || s.ip || "",
          port: statNumber(s.port),
          priority: statNumber(s.priority),
          networkType: s.networkType || "",
          relayProtocol: s.relayProtocol || ""
        });
      });

      var pairDetail = "";
      if (selectedPair) {
        var l = candidates[selectedPair.localCandidateId];
        var r = candidates[selectedPair.remoteCandidateId];
        var la = (l && (l.address || l.ip)) || "?";
        var ra = (r && (r.address || r.ip)) || "?";
        pairDetail = la + " <-> " + ra;
        if (previous.pair !== pairDetail) {
          previous.pair = pairDetail;
          beacon({ type: "selected-pair", pc: pcId, detail: pairDetail, private: isPrivate(la) || isPrivate(ra) });
        }
      }

      var certificates = [];
      var linked = [];
      if (transport) {
        if (transport.localCertificateId && certs[transport.localCertificateId]) linked.push({ role: "local", cert: certs[transport.localCertificateId] });
        if (transport.remoteCertificateId && certs[transport.remoteCertificateId]) linked.push({ role: "remote", cert: certs[transport.remoteCertificateId] });
      }
      if (!linked.length) stats.forEach(function (s) { if (s.type === "certificate") linked.push({ role: "unknown", cert: s }); });
      linked.slice(0, 4).forEach(function (entry) {
        var c = entry.cert;
        var base64 = typeof c.base64Certificate === "string" ? c.base64Certificate : "";
        var fingerprint = c.fingerprint || "";
        certificates.push({ role: entry.role, algorithm: c.fingerprintAlgorithm || "", fingerprint: fingerprint });
        var signature = (c.fingerprintAlgorithm || "") + ":" + fingerprint + ":" + base64;
        if (previous["cert-" + c.id] !== signature) {
          previous["cert-" + c.id] = signature;
          beacon({ type: "dtls-cert", pc: pcId, role: entry.role, algorithm: c.fingerprintAlgorithm || "",
            fingerprint: fingerprint, base64: base64.slice(0, 16384), truncated: base64.length > 16384 });
        }
      });

      var truncated = rtp.length > 24 || candidateStats.length > 32;
      beacon({
        type: "stats-snapshot", pc: pcId, truncated: truncated,
        transport: transport ? {
          dtlsRole: transport.dtlsRole || "", iceRole: transport.iceRole || "",
          dtlsState: transport.dtlsState || "", dtlsCipher: transport.dtlsCipher || "",
          srtpCipher: transport.srtpCipher || "", tlsVersion: transport.tlsVersion || ""
        } : null,
        pair: pairDetail,
        rtp: rtp.slice(0, 24),
        candidates: candidateStats.slice(0, 32),
        certificates: certificates
      });
    }).catch(function () {});
  }

  function wrapGetUserMedia() {
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      var orig = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = function (constraints) {
        beacon({ type: "getUserMedia", constraints: safeJson(constraints) });
        var request;
        try {
          request = orig(constraints);
        } catch (error) {
          beacon({ type: "getUserMedia-result", outcome: "rejected", error: cleanError(error) });
          throw error;
        }
        // Observe only the outcome and browser error; never collect track data,
        // device labels, or media contents.
        request.then(function () {
          beacon({ type: "getUserMedia-result", outcome: "resolved" });
        }, function (error) {
          beacon({ type: "getUserMedia-result", outcome: "rejected", error: cleanError(error) });
        });
        return request;
      };
    }
  }

  function sizeOf(data) {
    try {
      if (data == null) return 0;
      if (typeof data === "string") return new TextEncoder().encode(data).byteLength;
      if (data.byteLength != null) return data.byteLength;
      if (data.size != null) return data.size;
    } catch (e) {}
    return 0;
  }

  function safeJson(o) {
    try { return JSON.stringify(o); } catch (e) { return String(o); }
  }

  function pollCommands() {
    if (!COMMAND) return;
    function loop() {
      if (unloading) return;
      heartbeat();
      requestBridge({ poll: "1" })
        .then(function (doc) {
          if (!doc || !Array.isArray(doc.commands)) return;
          doc.commands.filter(function (c) {
            return c.type === "dc-fuzz" || c.type === "ice-probe" || c.type === "sdp-fuzz" ||
              c.type === "capture-stats" || c.type === "signaling-flood";
          }).forEach(dispatchCommand);
        })
        .catch(function () {})
        .then(function () { setTimeout(loop, 3000); });
    }
    loop();
  }

  function heartbeat() {
    return beacon({ type: "agent-state", version: AGENT_VERSION,
      iceServers: observedIceServers.reduce(function (urls, s) {
        var list = Array.isArray(s.urls) ? s.urls : [s.urls];
        for (var i = 0; i < list.length; i++) if (list[i] && urls.indexOf(list[i]) < 0) urls.push(list[i]);
        return urls;
      }, []),
      iceServerDetails: observedIceServers,
      channels: Array.from(channels.entries()).map(function (pair) {
        return { channelId: pair[0], pc: pair[1].pcId, label: pair[1].dc.label, state: pair[1].dc.readyState };
      }), completed: completedCommands });
  }

  async function authorized(command) {
    if (unloading || location.href !== command.frame) return false;
    var doc = await requestBridge({ authorize: command.id });
    return !unloading && location.href === command.frame && !!doc && doc.authorized === true;
  }

  function dispatchCommand(command) {
    if (command.agent !== AGENT_ID || command.frame !== location.href || !command.id || seenCommands.has(command.id) || activeCommand) return;
    seenCommands.add(command.id);
    if (seenCommands.size > 256) seenCommands.delete(seenCommands.values().next().value);
    activeCommand = command.id;
    Promise.resolve().then(async function () {
      if (!await authorized(command)) return "cancelled";
      if (command.type === "dc-fuzz") return runFuzz(command);
      if (command.type === "sdp-fuzz") return runSdpFuzz(command);
      if (command.type === "capture-stats") return runCaptureStats(command);
      if (command.type === "signaling-flood") return runSignalingFlood(command);
      return runIceProbe(command);
    }).catch(function (e) {
      var errType = command.type === "dc-fuzz" ? "fuzz-error"
        : command.type === "sdp-fuzz" ? "sdp-fuzz-error"
        : command.type === "capture-stats" ? "stats-capture-error"
        : command.type === "signaling-flood" ? "signaling-flood-error"
        : "ice-probe-error";
      var errorEvent = { type: errType, commandId: command.id, detail: cleanError(e) };
      if (errType === "ice-probe-error") iceProbeEvent(command, errorEvent); else beacon(errorEvent);
      return "failed";
    }).then(function (status) {
      completedCommands.push({ commandId: command.id, status: status });
      if (completedCommands.length > 32) completedCommands.shift();
      beacon({ type: "command-result", commandId: command.id, module: command.type, status: status,
        detail: command.type + " " + command.id.slice(0, 8) + " " + status });
      activeCommand = null;
    });
  }

  function cleanError(error) {
    // Credentials are preserved in error detail on purpose. The tester controls
    // what is removed from screenshots and report evidence; nothing is redacted.
    var message = (error.name || "Error") + ": " + (error.message || String(error));
    return message.slice(0, 1024);
  }

  function fuzzPayload(cfg, index) {
    if (cfg.mode === "text") return cfg.payload;
    if (cfg.mode === "hex") {
      var hex = cfg.payload.replace(/\s/g, "");
      if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) throw new Error("Invalid hex payload");
      return new Uint8Array((hex.match(/../g) || []).map(function (b) { return parseInt(b, 16); }));
    }
    if (cfg.mode === "json") {
      var values = ['null', 'true', 'false', '0', '-1', '""', '{}', '[]', '{"type":null}', '{"value":9007199254740993}', '{"x":1,"x":2}', '{'];
      return values[index % values.length];
    }
    if (cfg.mode === "boundary") {
      var sizes = [0, 1, 255, 256, 1023, 1024, 4095, 4096, 16384, 65536].filter(function (n) { return n <= cfg.maxBytes; });
      if (sizes.indexOf(cfg.maxBytes) < 0) sizes.push(cfg.maxBytes);
      return "A".repeat(sizes[index % sizes.length]);
    }
    throw new Error("Unknown fuzz mode");
  }

  async function runFuzz(command) {
    var cfg = command.config, entry = channels.get(command.channelId), total = 0, errors = 0;
    if (!cfg || !Number.isInteger(cfg.count) || cfg.count < 1 || cfg.count > 50 ||
      !Number.isInteger(cfg.maxBytes) || cfg.maxBytes < 1 || cfg.maxBytes > 65536 || cfg.count * cfg.maxBytes > 1048576 ||
      !Number.isInteger(cfg.intervalMs) || cfg.intervalMs < 100 || cfg.intervalMs > 1000) throw new Error("Invalid fuzz limits");
    if (!entry) throw new Error("DataChannel no longer exists");
    for (var index = 0; index < cfg.count; index++) {
      if (index) await new Promise(function (resolve) { setTimeout(resolve, cfg.intervalMs); });
      if (!await authorized(command)) return "cancelled";
      var dc = entry.dc;
      if (dc.readyState !== "open") throw new Error("DataChannel is " + dc.readyState);
      if (dc.bufferedAmount > 262144) throw new Error("Stopped: DataChannel send buffer exceeds 256 KiB");
      var payload = fuzzPayload(cfg, index), bytes = sizeOf(payload);
      if (bytes > cfg.maxBytes || total + bytes > 1048576) throw new Error("Payload exceeds run byte limit");
      total += bytes;
      var event = { type: "fuzz-result", commandId: command.id, pc: entry.pcId, channelId: command.channelId,
        label: dc.label, index: index + 1, bytes: bytes, bufferedAmount: dc.bufferedAmount,
        preview: typeof payload === "string" ? payload.slice(0, 512) : Array.from(payload.slice(0, 256)).map(function (n) { return n.toString(16).padStart(2, "0"); }).join(" ") };
      try {
        var max = entry.pc.sctp && entry.pc.sctp.maxMessageSize;
        if (max > 0 && bytes > max) throw new Error("Payload exceeds negotiated SCTP maxMessageSize " + max);
        dc.send(payload);
        event.accepted = true; event.detail = "Message " + (index + 1) + ": " + bytes + " bytes accepted by send()";
      } catch (e) {
        errors++; event.accepted = false; event.detail = "Message " + (index + 1) + ": " + cleanError(e);
      }
      beacon(event);
      if (!event.accepted && cfg.stopOnError) return "failed";
    }
    return errors ? "failed" : "completed";
  }

  function iceProbeEvent(command, event) {
    var cfg = command.config || {};
    // Preserve the actual run inputs, not the current UI configuration, for comparison.
    event.url = cfg.url || "";
    event.username = cfg.username || "";
    event.credential = cfg.credential || "";
    beacon(event);
  }

  async function runIceProbe(command) {
    var cfg = command.config;
    if (!cfg || ["all", "relay"].indexOf(cfg.policy) < 0 || !Number.isInteger(cfg.timeoutSeconds) || cfg.timeoutSeconds < 3 || cfg.timeoutSeconds > 30) throw new Error("Invalid ICE probe settings");
    if (!NativePeerConnection) throw new Error("RTCPeerConnection is unavailable");
    var server = cfg.url ? { urls: cfg.url } : null;
    if (server && /^turns?:/i.test(cfg.url)) { server.username = cfg.username; server.credential = cfg.credential; }
    // Use the unwrapped constructor: probe SDP must not inherit M3 mutation rules.
    var pc = new NativePeerConnection({ iceServers: server ? [server] : [], iceTransportPolicy: cfg.policy });
    var started = Date.now(), counts = { host: 0, srflx: 0, relay: 0, prflx: 0 }, errors = 0;
    var finish, settled = false, timer, leaseTimer;
    var done = new Promise(function (resolve) { finish = function (reason) { if (!settled) { settled = true; resolve(reason); } }; });
    async function renew() {
      if (!await authorized(command)) finish("cancelled");
      if (!settled) leaseTimer = setTimeout(renew, 1000);
    }
    try {
      pc.addEventListener("icecandidate", function (e) {
        if (settled) return;
        if (!e.candidate) { finish("complete"); return; }
        var candidate = e.candidate;
        var type = candidate.type || (candidate.candidate.match(/ typ (\w+)/) || [])[1] || "unknown";
        counts[type] = (counts[type] || 0) + 1;
        iceProbeEvent(command, { type: "ice-probe-candidate", commandId: command.id, candidate: candidate.candidate,
          candidateType: type, protocol: candidate.protocol, address: candidate.address, port: candidate.port,
          elapsedMs: Date.now() - started, private: isPrivate(candidate.candidate), detail: type + " " + candidate.candidate });
      });
      pc.addEventListener("icecandidateerror", function (e) {
        if (settled) return;
        errors++;
        iceProbeEvent(command, { type: "ice-probe-error", commandId: command.id, errorCode: e.errorCode,
          detail: cleanError({ name: "ICE " + e.errorCode, message: e.errorText || "Candidate gathering error" }) });
      });
      timer = setTimeout(function () { finish("timeout"); }, cfg.timeoutSeconds * 1000);
      leaseTimer = setTimeout(renew, 1000);
      pc.createDataChannel("webrtc-ice-probe");
      // Race setup too, so a stalled browser API cannot leave a probe open indefinitely.
      var setup = Promise.resolve().then(function () { return pc.createOffer(); }).then(function (offer) {
        if (!settled) return pc.setLocalDescription(offer);
      }).then(function () { return done; });
      var reason = await Promise.race([setup, done]);
      var expected = cfg.url ? (/^turns?:/i.test(cfg.url) ? "relay" : "srflx") : "host";
      var observed = counts[expected] > 0;
      iceProbeEvent(command, { type: "ice-probe-result", commandId: command.id, reason: reason, counts: counts, errors: errors,
        expected: expected, observed: observed, elapsedMs: Date.now() - started,
        detail: reason + ": " + expected + (observed ? " candidate observed" : " candidate not observed") });
      return reason === "cancelled" ? "cancelled" : (observed ? "completed" : "failed");
    } finally {
      settled = true; clearTimeout(timer); clearTimeout(leaseTimer); pc.close();
    }
  }

  // Manual "Capture stats": force a fresh getStats() snapshot for every live
  // application peer on the page. Bounded by the peer registry (32) and the
  // snapshot caps in reportStats().
  async function runCaptureStats(command) {
    var live = peersSeen.filter(function (entry) {
      return entry.pc.connectionState !== "closed" && entry.pc.signalingState !== "closed";
    });
    if (!live.length) throw new Error("No live RTCPeerConnection on this page; join a call first");
    for (var i = 0; i < live.length; i++) {
      if (!await authorized(command)) return "cancelled";
      await reportStats(live[i].pc, live[i].pcId);
    }
    beacon({ type: "stats-capture-result", commandId: command.id, peers: live.length,
      detail: "Captured a getStats snapshot for " + live.length + " live peer(s)." });
    return "completed";
  }

  // T8 — bounded, opt-in local renegotiation/ICE-restart loop. It only drives
  // createOffer/setLocalDescription on a throwaway peer (no signaling is sent),
  // so it probes how the page's own negotiation machinery behaves and whether
  // ICE credentials are reused across restarts. Hard caps: 1-20 attempts,
  // 500-5000 ms apart, cancellation checked before every attempt.
  async function runSignalingFlood(command) {
    var cfg = command.config;
    if (!cfg || cfg.confirm !== true) throw new Error("Signaling flood is opt-in; enable it explicitly");
    if (!Number.isInteger(cfg.count) || cfg.count < 1 || cfg.count > 20 ||
      !Number.isInteger(cfg.intervalMs) || cfg.intervalMs < 500 || cfg.intervalMs > 5000) throw new Error("Invalid flood limits");
    if (!NativePeerConnection) throw new Error("RTCPeerConnection is unavailable");
    var pc = new NativePeerConnection({});
    var seen = {}, distinct = 0, reused = 0;
    try {
      for (var index = 0; index < cfg.count; index++) {
        if (index) await new Promise(function (resolve) { setTimeout(resolve, cfg.intervalMs); });
        if (!await authorized(command)) return "cancelled";
        var offer = await pc.createOffer({ iceRestart: index > 0 });
        await pc.setLocalDescription(offer);
        var ufrag = (offer.sdp.match(/a=ice-ufrag:(\S+)/) || [])[1] || "";
        var pwd = (offer.sdp.match(/a=ice-pwd:(\S+)/) || [])[1] || "";
        var key = ufrag + ":" + pwd, isReuse = seen[key] === true;
        if (isReuse) reused++; else { seen[key] = true; distinct++; }
        beacon({ type: "flood-result", commandId: command.id, index: index + 1, iceUfrag: ufrag, icePwd: pwd,
          reused: isReuse, detail: "Local renegotiation " + (index + 1) + "/" + cfg.count + " completed" });
      }
      beacon({ type: "signaling-flood-summary", commandId: command.id, attempts: cfg.count, distinctCredentials: distinct,
        reusedCredentials: reused,
        detail: cfg.count + " local ICE-restart renegotiation(s): " + distinct + " distinct ICE credential pair(s), " +
          reused + " reuse(s). Nothing was sent to the signaling server." });
      return "completed";
    } finally { try { pc.close(); } catch (e) {} }
  }

  function makeBaseOffer() {
    return Promise.resolve().then(function () {
      var pc = new NativePeerConnection({});
      pc.createDataChannel("sdp-fuzz-base");
      return Promise.resolve(pc.createOffer()).then(function (offer) {
        try { pc.close(); } catch (e) {}
        return offer && offer.sdp ? offer.sdp : "";
      }, function () { try { pc.close(); } catch (e) {} return ""; });
    }).catch(function () { return ""; }).then(function (sdp) {
      return sdp || "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n" +
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n" +
        "a=setup:actpass\r\na=fingerprint:sha-256 00\r\na=rtpmap:0 opus/48000\r\n";
    });
  }

  // Mutate every line of the latest observed application SDP with known SDP
  // attributes, malformed line types, integer overflow values and bounded long
  // values. The fixed cases add whole-description structural and size boundaries.
  function sdpFuzzCases(base) {
    var lines = base.split(/\r?\n/).filter(function (line, i, all) { return line.length || i < all.length - 1; });
    var cases = [{ label: "baseline-observed", sdp: base }];
    var perMutation = Array.from({ length: 7 }, function () { return []; });
    function changedLine(index, value, label, mutationIndex) {
      var changed = lines.slice();
      if (label === "deleted") changed.splice(index, 1); else changed[index] = value;
      perMutation[mutationIndex].push({ label: "line-" + (index + 1) + "-" + label, lineNumber: index + 1,
        mutatedLine: value, sdp: changed.join("\r\n") + "\r\n" });
    }
    lines.forEach(function (line, index) {
      var numeric = line.replace(/-?\d{1,20}/g, "999999999999999999999999999999");
      changedLine(index, "", "deleted", 0);
      changedLine(index, "a=rtpmap:127 opus/48000/2", "known-rtpmap", 1);
      changedLine(index, "a=fmtp:127 minptime=10;useinbandfec=1", "known-fmtp", 2);
      changedLine(index, "a=candidate:1 1 UDP 2122260223 127.0.0.1 9 typ host", "known-candidate", 3);
      changedLine(index, numeric === line ? line + " 999999999999999999999999999999" : numeric, "integer-overflow", 4);
      changedLine(index, line.slice(0, 128) + "X".repeat(4096), "long-attribute-4k", 5);
    });
    // Codec-focused mutations: rewrite each a=rtpmap / a=fmtp line with malformed
    // clock rates, channel counts, payload types, and known H.264/Opus parameter
    // payloads, so the parser is exercised per codec rather than only per line.
    lines.forEach(function (line, index) {
      if (/^a=rtpmap:/i.test(line)) {
        changedLine(index, "a=rtpmap:2147483648 H264/90000", "codec-payload-overflow", 6);
        changedLine(index, "a=rtpmap:127 opus/0/999999999", "codec-rate-channel-overflow", 6);
        changedLine(index, "a=rtpmap:", "codec-empty-rtpmap", 6);
      }
      if (/^a=fmtp:/i.test(line)) {
        changedLine(index, "a=fmtp:127 profile-level-id=FFFFFFFF;packetization-mode=99", "codec-h264-profile-overflow", 6);
        changedLine(index, "a=fmtp:127 max-fs=999999999;max-mbps=999999999;minptime=-1;useinbandfec=9", "codec-opus-fmtp-malformed", 6);
        changedLine(index, "a=fmtp:127 " + "x=1;".repeat(512) + "x=1", "codec-fmtp-long-params", 6);
      }
    });
    var firstMedia = (base.match(/^m=.*$/m) || ["m=application 9 UDP/DTLS/SCTP webrtc-datachannel"])[0];
    cases.push(
      { label: "empty", sdp: "" },
      { label: "whitespace-only", sdp: "   \r\n\t\r\n" },
      { label: "missing-v", sdp: lines.filter(function (l) { return l.indexOf("v=") !== 0; }).join("\r\n") + "\r\n" },
      { label: "missing-o", sdp: lines.filter(function (l) { return l.indexOf("o=") !== 0; }).join("\r\n") + "\r\n" },
      { label: "no-media", sdp: lines.filter(function (l) { return l.indexOf("m=") !== 0; }).join("\r\n") + "\r\n" },
      { label: "truncated-half", sdp: base.slice(0, Math.floor(base.length / 2)) },
      { label: "oversized-attribute", sdp: base + "a=" + "X".repeat(8192) + "\r\n" },
      { label: "overflow-64k", sdp: base + "a=x" + "X".repeat(65536) + "\r\n" },
      { label: "overflow-256k", sdp: base + "a=x" + "X".repeat(262144) + "\r\n" },
      { label: "many-attributes", sdp: base + "a=x\r\n".repeat(2000) },
      { label: "many-media", sdp: base + (firstMedia + "\r\n").repeat(500) },
      { label: "non-numeric-port", sdp: base.replace(/^(m=\S+ )\d+/m, "$1NaN") },
      { label: "huge-payload-type", sdp: base + "a=rtpmap:999999999 opus/48000\r\n" },
      { label: "control-chars", sdp: base + "a=x\u0000\u0007\u001b[31m\r\n" },
      { label: "unicode-session", sdp: base.replace(/^s=.*$/m, "s=💥‮evil") },
      { label: "format-specifiers", sdp: base + "a=label:%n%n%s%x%p\r\n" },
      { label: "crlf-injection", sdp: base + "a=x\r\na=injected:1\r\n\r\nm=bogus 0 X 0\r\n" },
      { label: "codec-h264-profile-overflow", sdp: base + "a=fmtp:99 profile-level-id=FFFFFFFF;level-asymmetry-allowed=99\r\n" },
      { label: "codec-opus-malformed", sdp: base + "a=fmtp:111 minptime=99999;useinbandfec=9;maxaveragebitrate=-1\r\n" },
      { label: "codec-rtpmap-long-codec", sdp: base.replace(/^a=rtpmap:.*$/m, "a=rtpmap:111 " + "A".repeat(4096) + "/0/0") },
      { label: "duplicate-critical", sdp: base + "\r\n" + base }
    );
    // Sample mutation families before exhausting the cap on long real-call SDP.
    // The baseline remains first; codec, structural and per-line cases all get a turn.
    var structural = cases.splice(1);
    var groups = [perMutation[0], perMutation[6], structural].concat(perMutation.slice(1, 6));
    var remaining = true;
    for (var offset = 0; remaining; offset++) {
      remaining = false;
      groups.forEach(function (group) {
        if (offset < group.length) { cases.push(group[offset]); remaining = true; }
      });
    }
    return cases;
  }

  async function runSdpFuzz(command) {
    var cfg = command.config;
    if (!cfg || ["offer", "answer"].indexOf(cfg.descriptionType) < 0 ||
      !Number.isInteger(cfg.maxCases) || cfg.maxCases < 1 || cfg.maxCases > 500) throw new Error("Invalid SDP fuzz settings");
    if (!NativePeerConnection) throw new Error("RTCPeerConnection is unavailable");
    var base = cfg.descriptionType === "offer" ? latestObservedOffer : latestObservedAnswer;
    if (!base && cfg.descriptionType === "answer") throw new Error("Answer fuzzing needs an observed answer. Negotiate a connection first.");
    if (!base) base = await makeBaseOffer();
    if (base.length > 262144) throw new Error("Observed SDP exceeds the 256 KiB seed limit; refusing to truncate the baseline.");
    var cases = sdpFuzzCases(base).slice(0, cfg.maxCases);
    var accepted = 0, rejected = 0, answersGenerated = 0, baselineOutcome = "unknown";
    for (var i = 0; i < cases.length; i++) {
      if (!await authorized(command)) return "cancelled";
      var c = cases[i];
      var pc = new NativePeerConnection({});
      var event = { type: "sdp-fuzz-result", commandId: command.id, index: i + 1, label: c.label,
        descriptionType: cfg.descriptionType, bytes: new TextEncoder().encode(c.sdp).byteLength,
        preview: c.sdp.slice(0, 300), tail: c.sdp.slice(-300) };
      if (c.lineNumber) { event.lineNumber = c.lineNumber; event.mutatedLine = c.mutatedLine; }
      var stage = cfg.descriptionType === "answer" ? "setup" : "parser";
      try {
        if (cfg.descriptionType === "answer") {
          pc.createDataChannel("sdp-fuzz-answer-control");
          var localOffer = await pc.createOffer();
          await pc.setLocalDescription(localOffer);
        }
        stage = "parser";
        await pc.setRemoteDescription({ type: cfg.descriptionType, sdp: c.sdp });
        if (i > 0) accepted++; event.outcome = "accepted";
        event.detail = "Case " + c.label + " (" + event.bytes + " bytes): accepted by setRemoteDescription()";
        if (cfg.descriptionType === "offer") {
          try {
            var answer = await pc.createAnswer();
            event.followupOutcome = "answer-generated";
            event.answerBytes = answer && answer.sdp ? answer.sdp.length : 0;
            if (i > 0) answersGenerated++;
          } catch (answerError) {
            event.followupOutcome = "answer-rejected";
            event.followupError = cleanError(answerError);
          }
        } else {
          event.followupOutcome = "not-run-for-answer-mode";
        }
      } catch (e) {
        if (i > 0 && stage === "parser") rejected++;
        event.outcome = stage === "parser" ? "rejected" : "setup-error";
        event.error = cleanError(e);
        event.detail = "Case " + c.label + " (" + event.bytes + " bytes): " + event.error;
      } finally { try { pc.close(); } catch (e) {} }
      await beacon(event);
      if (stage === "setup") throw new Error("Could not prepare answer-mode peer: " + event.error);
      if (i === 0) {
        baselineOutcome = event.outcome;
        if (baselineOutcome !== "accepted") throw new Error("Baseline SDP was rejected; mutations were not run. " + event.error);
      }
    }
    await beacon({ type: "sdp-fuzz-summary", commandId: command.id, cases: cases.length, mutations: cases.length - 1,
      baselineOutcome: baselineOutcome, accepted: accepted, rejected: rejected, answersGenerated: answersGenerated,
      detail: (cases.length - 1) + " mutations: " + accepted + " accepted, " + rejected + " rejected; " +
        answersGenerated + " accepted mutations also produced an answer. Baseline accepted separately. API acceptance is not proof of a vulnerability." });
    return "completed";
  }

  try { wrapPeerConnection(); } catch (e) {}
  try { wrapGetUserMedia(); } catch (e) {}
  beacon({ type: "installed", detail: "agent " + AGENT_VERSION, private: false });
  if (typeof window.addEventListener === "function") window.addEventListener("pagehide", function () { unloading = true; });
  pollCommands();
})();
