import contextlib
import hashlib
import json
import socket
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import protocol_runner as rtc


class TurnFixture:
    def __init__(self, open_relay=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.open = open_relay
        self.closed = False
        self.allocations = set()
        self.receipts = []
        self.key = hashlib.md5(b"alice:lab:password").digest()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.closed:
            try:
                raw, address = self.sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if raw[:2] == b"\x40\x00":
                self.receipts.append(raw[4:])
                self.sock.sendto(raw, address)
                continue
            message = rtc.parse_stun(raw, key=self.key)
            method = message["type"]
            tx = bytes.fromhex(message["transaction"])
            attrs, key = [], None
            if method == 1:
                kind = 0x101
                attrs = [(0x8022, b"test-fixture")]
            elif method == 0x16:
                marker = rtc.first(message, 0x13)
                self.receipts.append(marker)
                self.sock.sendto(rtc.stun_message(0x17, tx, [(0x12, rtc.first(message, 0x12)), (0x13, marker)]), address)
                continue
            elif method == 3 and not self.open and not rtc.first(message, 6):
                kind = 0x113
                attrs = [(9, b"\0\0\x04\x01Unauthorized"), (0x14, b"lab"), (0x15, b"nonce")]
            elif not self.open and message["integrity"] is not True:
                kind = method | 0x110
                attrs = [(9, b"\0\0\x04\x29Wrong credentials")]
            else:
                kind = method | 0x100
                key = self.key if message["integrity"] else None
                if method == 3:
                    self.allocations.add(address)
                    attrs = [(0xD, struct.pack("!I", 60))]
                if method == 4:
                    lifetime = rtc.first(message, 0xD)
                    attrs = [(0xD, lifetime)]
                    if lifetime == b"\0\0\0\0":
                        self.allocations.discard(address)
            self.sock.sendto(rtc.stun_message(kind, tx, attrs, key), address)

    def close(self):
        self.closed = True
        self.sock.close()
        self.thread.join(1)

    def target(self):
        return dict(input=f"turn:127.0.0.1:{self.port}", host="127.0.0.1", port=self.port,
                    scheme="turn", transport="udp", scopeUrl=f"http://127.0.0.1:{self.port}/")


class ProtocolTests(unittest.TestCase):
    def test_integrity_transaction_lengths_and_integrity_boundary(self):
        tx, key = b"a" * 12, b"secret"
        packet = rtc.stun_message(3, tx, [(6, b"alice")], key)
        self.assertTrue(rtc.parse_stun(packet, tx, key)["integrity"])
        self.assertFalse(rtc.parse_stun(rtc.stun_message(3, tx, [], key, True), tx, key)["integrity"])
        with self.assertRaises(ValueError):
            rtc.parse_stun(packet, b"b" * 12, key)
        with self.assertRaises(ValueError):
            rtc.parse_stun(packet[:-1], tx, key)
        extra = rtc.attribute(0x12, b"attacker")
        modified = packet[:2] + struct.pack("!H", len(packet) - 20 + len(extra)) + packet[4:] + extra
        parsed = rtc.parse_stun(modified, tx, key)
        self.assertTrue(parsed["integrity"])
        self.assertEqual(rtc.first(parsed, 0x12), b"")

    def test_ipv4_and_ipv6_xor_roundtrip(self):
        for address in ("127.0.0.1", "2001:db8::1", "::1"):
            tx = b"b" * 12
            self.assertEqual(rtc.decode_address(rtc.xor_address(address, 9999, tx), tx), (address, 9999))

    def request(self, target, id="TRN-02"):
        return {"target": target, "testId": id, "engagementId": "lab", "runId": "run", "timeoutSeconds": 15,
                "credentials": [{"condition": "valid", "username": "alice", "password": "password"},
                                {"condition": "absent", "username": "", "password": ""},
                                {"condition": "incorrect", "username": "alice", "password": "wrong"}]}

    def test_auth_matrix_positive_negative_and_release(self):
        for open_relay in (False, True):
            with contextlib.closing(TurnFixture(open_relay)) as server:
                grants = []
                result = rtc.run_turn(self.request(server.target()), lambda *leg: grants.append(leg))
                self.assertEqual(result["execution"], "completed", result)
                self.assertEqual(result["control"], "passed")
                self.assertEqual(result["security"], "inconclusive")
                cases = [x["output"] for x in result["evidence"] if x["stage"] == "case"]
                self.assertEqual([x["allocated"] for x in cases], [True, open_relay, open_relay])
                self.assertFalse(server.allocations)
                self.assertGreater(len(grants), 4)

    def test_forwarding_needs_receipt_and_gates_peer(self):
        with contextlib.closing(TurnFixture()) as server:
            request = self.request(server.target(), "TRN-05")
            request["peer"] = dict(host="127.0.0.1", port=9999, scopeUrl="http://127.0.0.1:9999/")
            grants = []
            result = rtc.run_turn(request, lambda *leg: grants.append(leg))
            self.assertEqual(result["execution"], "completed", result)
            outcome = next(x["output"] for x in result["evidence"] if x["stage"] == "case")
            self.assertTrue(outcome["transfer"]["received"])
            self.assertTrue(outcome["channelTransfer"]["received"])
            self.assertEqual(len(server.receipts), 2)
            self.assertTrue(any(x[2] == 9999 for x in grants))
            self.assertFalse(server.allocations)

    def test_scope_denial_stops_before_socket_traffic(self):
        with contextlib.closing(TurnFixture()) as server:
            def deny(*leg):
                raise rtc.Blocked("revoked")
            result = rtc.run_turn(self.request(server.target()), deny)
            self.assertEqual(result["execution"], "blocked")
            self.assertFalse(server.allocations)

    def test_scenario_effect_not_http_status_determines_result(self):
        class Handler(BaseHTTPRequestHandler):
            vulnerable = False
            def do_GET(self):
                access = self.headers.get("Authorization") == "valid" or self.vulnerable
                body = json.dumps({"protected": "owned-marker"} if access else {"denied": True}).encode()
                self.send_response(200)  # Intentionally identical statuses in both controls.
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        try:
            control = dict(id="control", url=origin + "/protected", identity="alice",
                           assertion=dict(pointer="/json/protected", equals="owned-marker", meaning="protected-effect"))
            for vulnerable in (False, True):
                Handler.vulnerable = vulnerable
                negative = dict(id="negative", url=origin + "/protected", identity="absent",
                                assertion=dict(pointer="/json/protected" if vulnerable else "/json/denied",
                                               equals="owned-marker" if vulnerable else True,
                                               meaning="protected-effect" if vulnerable else "explicit-rejection"))
                scenario = dict(id="auth", testId="SIG-02", policy="Only Alice can read this owned marker", control=[control],
                                cases=[dict(id="absent", steps=[negative], expectation="rejected")], timeoutSeconds=15, intervalMs=100)
                result = rtc.run_scenario(dict(scenario=scenario, engagementId="lab", runId="run", identities=[
                    dict(name="alice", headers={"Authorization": "valid"}, origins=[origin])]), lambda *leg: None)
                self.assertEqual(result["execution"], "completed", result)
                self.assertEqual(result["security"], "policy-violation" if vulnerable else "demonstrated-rejection")
                self.assertEqual(result["control"], "passed")
        finally:
            server.shutdown(); server.server_close(); thread.join(1)


if __name__ == "__main__":
    unittest.main()
