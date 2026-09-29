const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(`${__dirname}/webrtc-agent.js`, 'utf8');
const SDP = 'v=0\r\na=fingerprint:sha-256 AA:BB\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=sendrecv\r\na=candidate:1 1 udp 1 192.168.1.2 5000 typ host\r\na=end-of-candidates\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=sctp-port:5000\r\n';

function harness(initial = {}) {
  const events = [], nativeCalls = [], requests = [], timers = new Map();
  let config = { enabled: true, target: 'remote', mediaDirection: 'unchanged', ...initial };
  let offline = false, rejectRemote = false, timerId = 0;
  class NativePeer {
    static generateCertificate() { return 'preserved'; }
    addEventListener() {}
    createOffer(options) {
      nativeCalls.push(['createOffer', options]);
      return Promise.resolve({ type: 'offer', sdp: SDP });
    }
    createAnswer() { return Promise.resolve({ type: 'answer', sdp: SDP }); }
    setLocalDescription(desc) { nativeCalls.push(['local', desc]); return Promise.resolve(); }
    setRemoteDescription(desc, callback) {
      nativeCalls.push(['remote', desc]);
      if (callback) { callback(); return undefined; }
      return rejectRemote ? Promise.reject(Object.assign(new Error('bad fingerprint'), { name: 'OperationError' })) : Promise.resolve();
    }
    addIceCandidate(candidate) { nativeCalls.push(['candidate', candidate]); return Promise.resolve(); }
  }
  const context = {
    navigator: {}, location: { href: 'https://example.test/call?room=1&user=2' }, AbortController, TextEncoder,
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    fetch: (url, options) => {
      if (options.method === 'POST') { events.push(JSON.parse(options.body)); return Promise.resolve({ ok: true }); }
      requests.push([url, options]);
      if (offline) return Promise.reject(new Error('offline'));
      const commands = config ? [{ type: 'sdp-mutation', config: { ...config } }] : [];
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ commands }) });
    },
    RTCPeerConnection: NativePeer,
    __WRTC_CFG__: { collect: 'http://127.0.0.1:8777/collect', command: 'http://127.0.0.1:8777/command' }
  };
  context.window = context;
  vm.runInNewContext(source, context);
  return { events, nativeCalls, requests, timers, context,
    peer: () => new context.RTCPeerConnection(),
    config: value => { config = value; }, offline: () => { offline = true; }, rejectRemote: () => { rejectRemote = true; }
  };
}

test('incoming mutation records before/after and native acceptance without changing caller object', async () => {
  const h = harness({ removeFingerprint: true });
  const desc = Object.freeze({ type: 'offer', sdp: SDP });
  await h.peer().setRemoteDescription(desc);
  assert.equal(desc.sdp, SDP);
  assert.equal(h.nativeCalls[0][1].sdp.includes('a=fingerprint:'), false);
  const event = h.events.find(e => e.type === 'sdp-mutation');
  assert.equal(event.before, SDP);
  assert.equal(event.after, h.nativeCalls[0][1].sdp);
  assert.equal(h.events.find(e => e.type === 'sdp-result').accepted, true);
  assert.equal(new URL(h.requests.at(-1)[0]).searchParams.get('frame'), h.context.location.href);
  assert.equal(h.requests.at(-1)[1].cache, 'no-store');
});

test('outgoing offers and answers mutate once; local setter receives same description', async () => {
  const h = harness({ target: 'local', find: 'a=sendrecv', replacement: 'a=sendrecvX' });
  const pc = h.peer();
  const offer = await pc.createOffer({ iceRestart: true });
  await pc.setLocalDescription(offer);
  const answer = await pc.createAnswer();
  assert.ok(offer.sdp.includes('a=sendrecvX\r\n'));
  assert.ok(answer.sdp.includes('a=sendrecvX\r\n'));
  assert.equal(h.nativeCalls.find(c => c[0] === 'local')[1], offer);
  assert.equal(h.events.filter(e => e.type === 'sdp-mutation').length, 2);
  assert.equal(h.context.RTCPeerConnection.generateCertificate(), 'preserved');
});

test('candidate removal and media direction preserve application sections and CRLF', async () => {
  const h = harness({ removeCandidates: true, mediaDirection: 'inactive' });
  await h.peer().setRemoteDescription({ type: 'offer', sdp: SDP });
  const out = h.nativeCalls[0][1].sdp;
  assert.ok(!out.includes('a=candidate:') && !out.includes('a=end-of-candidates'));
  assert.ok(out.includes('a=inactive\r\nm=application'));
  assert.ok(out.endsWith('a=sctp-port:5000\r\n'));
  assert.equal((out.match(/a=inactive/g) || []).length, 1);
});

test('direction is added per audio/video section even when inherited from session', async () => {
  const h = harness({ mediaDirection: 'recvonly' });
  await h.peer().setRemoteDescription({ type: 'offer', sdp: 'v=0\na=sendonly\nm=audio 9 RTP/AVP 0\na=mid:0\nm=video 9 RTP/AVP 96\na=mid:1\n' });
  assert.equal(h.nativeCalls[0][1].sdp, 'v=0\na=sendonly\nm=audio 9 RTP/AVP 0\na=mid:0\na=recvonly\nm=video 9 RTP/AVP 96\na=mid:1\na=recvonly\n');
});

test('literal replacement normalizes multiline text and does not interpret dollar signs', async () => {
  const h = harness({ find: 'v=0\na=fingerprint:sha-256 AA:BB', replacement: 'v=0\na=literal:$&' });
  await h.peer().setRemoteDescription({ type: 'answer', sdp: SDP });
  assert.ok(h.nativeCalls[0][1].sdp.startsWith('v=0\r\na=literal:$&\r\n'));
});

test('disabled, wrong peer, wrong direction, revoked policy and offline bridge leave SDP unchanged', async () => {
  for (const rules of [null, { enabled: false }, { enabled: true, target: 'local', removeFingerprint: true },
    { enabled: true, target: 'remote', pcId: 'pc2', removeFingerprint: true }]) {
    const h = harness(); h.config(rules);
    const desc = { type: 'offer', sdp: SDP };
    await h.peer().setRemoteDescription(desc);
    assert.equal(h.nativeCalls[0][1], desc);
    assert.equal(h.events.filter(e => e.type === 'sdp-mutation').length, 0);
  }
  const h = harness({ removeFingerprint: true });
  const pc = h.peer(), desc = { type: 'offer', sdp: SDP };
  await pc.setRemoteDescription(desc);
  h.config(null);
  await pc.setRemoteDescription(desc);
  assert.equal(h.nativeCalls[1][1], desc);
  h.offline();
  await pc.setRemoteDescription(desc);
  assert.equal(h.nativeCalls[2][1], desc);
});

test('native rejection is reported and propagated, then later operations still work', async () => {
  const h = harness({ removeFingerprint: true });
  h.rejectRemote();
  const pc = h.peer();
  await assert.rejects(pc.setRemoteDescription({ type: 'offer', sdp: SDP }), /bad fingerprint/);
  const error = h.events.find(e => e.type === 'sdp-error');
  assert.equal(error.accepted, false);
  assert.ok(error.mutationId);
  await pc.addIceCandidate({ candidate: 'test' });
  assert.equal(h.nativeCalls.at(-1)[0], 'candidate');
});

test('description and trickle ICE operations retain their call order', async () => {
  const h = harness({ removeFingerprint: true });
  const pc = h.peer();
  await Promise.all([pc.setRemoteDescription({ type: 'offer', sdp: SDP }), pc.addIceCandidate({ candidate: 'test' }), pc.setLocalDescription()]);
  assert.deepEqual(h.nativeCalls.map(c => c[0]), ['remote', 'candidate', 'local']);
  assert.equal(h.nativeCalls[2][1], undefined);
});

test('rollback and legacy callback setters pass through intact', async () => {
  const h = harness({ removeFingerprint: true });
  const pc = h.peer(), desc = { type: 'rollback', sdp: '' };
  await pc.setRemoteDescription(desc);
  assert.equal(h.nativeCalls[0][1], desc);
  let called = false;
  const legacy = { type: 'offer', sdp: SDP };
  assert.equal(pc.setRemoteDescription(legacy, () => { called = true; }), undefined);
  assert.equal(called, true);
  assert.equal(h.nativeCalls[1][1], legacy);
});

test('replacement expansion is bounded and does not break the original call', async () => {
  const h = harness({ find: '0', replacement: 'x'.repeat(4096) });
  const desc = { type: 'offer', sdp: '0'.repeat(1000) };
  await h.peer().setRemoteDescription(desc);
  assert.equal(h.nativeCalls[0][1], desc);
  assert.ok(h.events.some(e => e.type === 'sdp-error' && e.detail.includes('limit')));
});

test('a stalled bridge times out and passes through the original SDP', async () => {
  const h = harness({ removeFingerprint: true });
  h.context.fetch = (url, options) => options.method === 'POST' ? Promise.resolve({ ok: true }) : new Promise(() => {});
  const desc = { type: 'offer', sdp: SDP };
  const operation = h.peer().setRemoteDescription(desc);
  await new Promise(resolve => setImmediate(resolve));
  for (const timer of h.timers.values()) if (timer.delay === 1500) timer.fn();
  await operation;
  assert.equal(h.nativeCalls[0][1], desc);
});
