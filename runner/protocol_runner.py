"""Bundled, dependency-free RTC runner. Apache-2.0. JSON-lines IPC, never shell commands.

Every connect/send requires a fresh grant from the Burp parent for both the named
listener and the pinned IP. Redirects/alternate servers are evidence, never followed.
"""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qsl, urlencode

VERSION = "1.1.3"
COOKIE = 0x2112A442
MAX_OUTPUT = 2_000_000


def now():
    return datetime.now(timezone.utc).isoformat()


class Blocked(Exception):
    pass


def parent_grant(url, address, port):
    print(json.dumps({"authorize": {"url": url, "address": address, "port": port}}), flush=True)
    answer = sys.stdin.readline(4096)
    if not answer or json.loads(answer).get("allowed") is not True:
        raise Blocked("Network leg is no longer authorized")


class Budget:
    def __init__(self, seconds=60, messages=200, bytes_limit=1_048_576):
        self.deadline = time.monotonic() + seconds
        self.remaining = messages
        self.bytes = bytes_limit

    def check(self, size=0):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Execution budget expired")
        self.remaining -= 1
        self.bytes -= size
        if self.remaining < 0 or self.bytes < 0:
            raise ValueError("Packet/message/byte budget exhausted")


class Connection:
    def __init__(self, target, budget, grant=parent_grant):
        self.target, self.budget, self.grant = target, budget, grant
        self.sock = None
        infos = socket.getaddrinfo(target["host"], target["port"], 0,
                                   socket.SOCK_DGRAM if target["transport"] == "udp" else socket.SOCK_STREAM)
        family, kind, proto, _, sockaddr = infos[0]
        self.address = sockaddr[0]
        self.permit()
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(min(3, max(0.1, budget.deadline - time.monotonic())))
            sock.connect(sockaddr)
            if target["transport"] == "tls":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=target["host"])
            self.sock = sock
        except BaseException:
            sock.close()
            raise

    def permit(self, size=0):
        self.budget.check(size)
        self.grant(self.target["scopeUrl"], self.address, self.target["port"])

    def send(self, data):
        self.permit(len(data))
        self.sock.sendall(data)

    def read(self, size):
        self.sock.settimeout(min(3, max(0.1, self.budget.deadline - time.monotonic())))
        data = self.sock.recv(size)
        self.budget.bytes -= len(data)
        if self.budget.bytes < 0:
            raise ValueError("Receive byte budget exceeded")
        return data

    def exact(self, size):
        if not 0 <= size <= 1_048_576:
            raise ValueError("Oversized frame")
        out = bytearray()
        while len(out) < size:
            data = self.read(size - len(out))
            if not data:
                raise EOFError("Peer closed before complete response")
            out.extend(data)
        return bytes(out)

    def close(self):
        if self.sock:
            self.sock.close()


def attribute(kind, value):
    return struct.pack("!HH", kind, len(value)) + value + b"\0" * ((-len(value)) % 4)


def stun_message(kind, transaction, attrs=(), key=None, bad_integrity=False):
    data = b"".join(attribute(k, v) for k, v in attrs)
    header = struct.pack("!HHI12s", kind, len(data) + (24 if key else 0), COOKIE, transaction)
    if key:
        digest = hmac.new(key, header + data, hashlib.sha1).digest()
        if bad_integrity:
            digest = bytes([digest[0] ^ 1]) + digest[1:]
        data += attribute(0x0008, digest)
    return header + data


def parse_stun(data, expected=None, key=None):
    if len(data) < 20:
        raise ValueError("Truncated STUN header")
    kind, length, cookie, transaction = struct.unpack("!HHI12s", data[:20])
    if cookie != COOKIE or kind & 0xC000 or length % 4 or len(data) != 20 + length:
        raise ValueError("Invalid STUN framing")
    if expected is not None and transaction != expected:
        raise ValueError("STUN transaction mismatch")
    attrs, offset, integrity = [], 20, None
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("Truncated attribute")
        tag, size = struct.unpack("!HH", data[offset:offset + 4])
        end = offset + 4 + size
        if end > len(data):
            raise ValueError("Attribute exceeds message")
        value = data[offset + 4:end]
        if tag == 0x0008:
            if integrity is not None or size != 20:
                raise ValueError("Invalid duplicate MESSAGE-INTEGRITY")
            header = data[:2] + struct.pack("!H", end - 20) + data[4:20]
            integrity = bool(key and hmac.compare_digest(hmac.new(key, header + data[20:offset], hashlib.sha1).digest(), value))
        # Never interpret semantic attributes beyond the integrity boundary.
        if integrity is None:
            attrs.append((tag, value))
        offset = end + (-size) % 4
    return {"type": kind, "transaction": transaction.hex(), "attrs": attrs, "integrity": integrity}


def first(message, tag, default=b""):
    return next((value for kind, value in message["attrs"] if kind == tag), default)


def error_code(message):
    error = first(message, 0x0009)
    return ((error[2] & 7) * 100 + error[3]) if len(error) >= 4 else None


def xor_address(address, port, transaction):
    ip = ipaddress.ip_address(address)
    mask = struct.pack("!I", COOKIE) + transaction
    return struct.pack("!BBH", 0, 1 if ip.version == 4 else 2, port ^ (COOKIE >> 16)) + bytes(a ^ b for a, b in zip(ip.packed, mask))


def decode_address(value, transaction):
    if len(value) < 4 or value[1] not in (1, 2):
        raise ValueError("Invalid XOR address")
    size = 4 if value[1] == 1 else 16
    if len(value) != size + 4:
        raise ValueError("Invalid XOR address length")
    mask = struct.pack("!I", COOKIE) + transaction
    return str(ipaddress.ip_address(bytes(a ^ b for a, b in zip(value[4:], mask)))), struct.unpack("!H", value[2:4])[0] ^ (COOKIE >> 16)


class TurnClient:
    def __init__(self, connection, username="", password=""):
        self.connection, self.username, self.password = connection, username, password
        self.realm, self.nonce, self.key, self.allocated = b"", b"", None, False
        self.evidence = []

    def receive(self):
        if self.connection.target["transport"] == "udp":
            return self.connection.read(65536)
        prefix = self.connection.exact(4)
        length = struct.unpack("!H", prefix[2:4])[0]
        if prefix[0] & 0xC0 == 0x40:
            return prefix + self.connection.exact(length + (-length) % 4)
        return prefix + self.connection.exact(16 + length)

    def request(self, method, attrs=(), authenticate=True, retry=True):
        transaction = os.urandom(12)
        auth = [(0x0006, self.username.encode()), (0x0014, self.realm), (0x0015, self.nonce)] if self.key and authenticate else []
        packet = stun_message(method, transaction, list(attrs(transaction) if callable(attrs) else attrs) + auth, self.key if authenticate else None)
        self.connection.send(packet)
        raw = self.receive()
        response = parse_stun(raw, transaction, self.key)
        self.evidence.append({"stage": "wire", "timestamp": now(), "input": {"hex": packet.hex()},
                              "output": {"hex": raw.hex(), "type": response["type"], "error": error_code(response), "integrity": response["integrity"]}})
        if response["type"] not in (method | 0x100, method | 0x110):
            raise ValueError("Unexpected STUN response method/class")
        if error_code(response) in (401, 438) and authenticate and self.username and retry:
            self.realm, self.nonce = first(response, 0x14), first(response, 0x15)
            if not self.realm or not self.nonce:
                raise ValueError("Challenge lacks realm/nonce")
            self.key = hashlib.md5(self.username.encode() + b":" + self.realm + b":" + self.password.encode()).digest()
            return self.request(method, attrs, authenticate=True, retry=False)
        if method == 3 and response["type"] == 0x103:
            self.allocated = True
        if self.key and response["type"] & 0x110 == 0x100 and response["integrity"] is not True:
            raise ValueError("Authenticated success lacks valid MESSAGE-INTEGRITY")
        return response

    def allocate(self):
        return self.request(3, [(0x0019, b"\x11\0\0\0"), (0x000D, struct.pack("!I", 60))])

    def release(self):
        if not self.allocated:
            return "not-required"
        response = self.request(4, [(0x000D, b"\0\0\0\0")])
        released = response["type"] == 0x104 and first(response, 0x000D) == b"\0\0\0\0"
        self.allocated = not released
        return "released" if released else "unconfirmed"

    def echo(self, peer, channel=False):
        # The relay destination is authorized separately; permission is never a receipt.
        address = socket.getaddrinfo(peer["host"], peer["port"], 0, socket.SOCK_DGRAM)[0][4][0]
        self.connection.grant(peer["scopeUrl"], address, peer["port"])
        result = self.request(9 if channel else 8, lambda tx: [(0x0012, xor_address(address, peer["port"], tx))] + ([(0x000C, b"\x40\x00\0\0")] if channel else []))
        if result["type"] != (0x109 if channel else 0x108):
            return {"permission": False, "received": False, "error": error_code(result)}
        marker = ("wrtc-" + uuid.uuid4().hex).encode()
        self.connection.grant(peer["scopeUrl"], address, peer["port"])
        if channel:
            wire = struct.pack("!HH", 0x4000, len(marker)) + marker
            if self.connection.target["transport"] != "udp":
                wire += b"\0" * ((-len(marker)) % 4)
        else:
            transaction = os.urandom(12)
            wire = stun_message(0x16, transaction, [(0x12, xor_address(address, peer["port"], transaction)), (0x13, marker)])
        self.connection.send(wire)
        raw = self.receive()
        if channel and len(raw) >= 4 and raw[:2] == b"\x40\x00":
            length = struct.unpack("!H", raw[2:4])[0]
            received = raw[4:4 + length] == marker and len(raw) >= 4 + length
        else:
            response = parse_stun(raw)
            remote = decode_address(first(response, 0x12), bytes.fromhex(response["transaction"]))
            received = response["type"] == 0x17 and remote == (address, peer["port"]) and first(response, 0x13) == marker
        return {"permission": True, "received": received, "marker": marker.decode(), "responseHex": raw.hex(),
                "peer": [address, peer["port"]], "path": "ChannelData" if channel else "Send/Data"}


def run_turn(request, grant=parent_grant):
    target, test_id = request["target"], request["testId"]
    budget = Budget(request.get("timeoutSeconds", 60))
    result = {"schema": 1, "engagementId": request["engagementId"], "runId": request["runId"], "testId": test_id,
              "target": target["input"], "backend": "bundled-turn", "backendVersion": VERSION, "startedAt": now(),
              "execution": "completed", "security": "observed", "confidence": "low", "severity": "information",
              "control": "not-run", "cleanup": "not-required", "evidence": [], "limitations": []}
    variants = request.get("credentials", [])
    if test_id != "TRN-02":
        variants = variants[:1] or [{"condition": "absent", "username": "", "password": ""}]
    outcomes, cleanup = [], []
    for identity in variants:
        connection = client = None
        try:
            connection = Connection(target, budget, grant)
            client = TurnClient(connection, identity.get("username", ""), identity.get("password", ""))
            if test_id == "TRN-01":
                response = client.request(1, authenticate=False)
                outcome = {"condition": identity["condition"], "binding": response["type"] == 0x101,
                           "software": first(response, 0x8022).decode(errors="replace"), "realm": first(response, 0x14).decode(errors="replace"),
                           "error": error_code(response), "alternateServerHex": first(response, 0x8023).hex()}
            else:
                response = client.allocate()
                outcome = {"condition": identity["condition"], "allocated": client.allocated, "error": error_code(response),
                           "realm": client.realm.decode(errors="replace"), "nonce": client.nonce.decode(errors="replace")}
                if client.allocated and test_id in ("TRN-04", "TRN-05"):
                    if not request.get("peer"):
                        raise ValueError("Select a scoped controlled UDP echo destination")
                    outcome["transfer"] = client.echo(request["peer"])
                    if test_id == "TRN-05":
                        outcome["channelTransfer"] = client.echo(request["peer"], channel=True)
                if client.allocated and test_id == "TRN-07":
                    refresh = client.request(4, [(0xD, struct.pack("!I", 60))])
                    outcome["refresh"] = refresh["type"] == 0x104
            outcomes.append(outcome)
            result["evidence"].append({"stage": "case", "timestamp": now(), "input": identity, "output": outcome})
        except (TimeoutError, socket.timeout) as exc:
            result["execution"] = "timeout"
            result["limitations"].append(str(exc))
        except Blocked as exc:
            result["execution"] = "blocked"
            result["limitations"].append(str(exc))
        except Exception as exc:
            result["execution"] = "partial"
            result["limitations"].append(str(exc))
        finally:
            if client:
                try:
                    cleanup.append(client.release())
                except Exception as exc:
                    cleanup.append("unconfirmed: " + str(exc))
                result["evidence"].extend(client.evidence)
            if connection:
                connection.close()
        if result["execution"] != "completed":
            break
    result["cleanup"] = "; ".join(cleanup) or "not-required"
    if any(x.startswith("unconfirmed") for x in cleanup):
        result["limitations"].append("Allocation release unconfirmed; requested lifetime was 60 seconds, server lifetime may differ")
    if test_id == "TRN-02":
        good = any(x.get("allocated") and x["condition"] == "valid" for x in outcomes)
        result["control"] = "passed" if good else "failed"
        result["security"] = "inconclusive"
        result["limitations"].append("Allocation acceptance is not relay transfer. Expired/revoked conditions require supplied credentials with known lifecycle evidence.")
    if test_id == "TRN-01":
        result["limitations"].append("Unauthenticated STUN Binding is expected in many deployments. Alternate servers are not followed. UDP relaying only; RFC 6062 and DTLS listeners need another adapter.")
    if test_id == "TRN-07":
        result["limitations"].append("This checks refresh/release only; cross-account ownership, reservations and logout policy require paired scenarios.")
    result["endedAt"] = now()
    return result


def pointer(value, path):
    if path == "":
        return value
    if not path.startswith("/"):
        raise ValueError("Expected a JSON pointer")
    for key in path[1:].split("/"):
        key = key.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and key.isdecimal() and int(key) < len(value):
            value = value[int(key)]
        else:
            return None
    return value


def target_for(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https", "ws", "wss") or not parsed.hostname or parsed.username or parsed.fragment:
        raise ValueError("Scenario URL must be http(s) or ws(s), without userinfo/fragment")
    if any(c in url for c in "\r\n\0"):
        raise ValueError("Invalid URL")
    secure = parsed.scheme in ("https", "wss")
    scope = parsed._replace(scheme="https" if secure else "http").geturl()
    return {"input": url, "scheme": parsed.scheme, "host": parsed.hostname,
            "port": parsed.port or (443 if secure else 80), "transport": "tls" if secure else "tcp", "scopeUrl": scope}


def http_request(connection, method, url, headers, body):
    if method not in {"GET", "HEAD", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"}:
        raise ValueError("Unsupported HTTP method")
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {k: v for k, v in headers.items() if k.lower() not in {"host", "content-length", "transfer-encoding", "connection"}}
    headers.update({"Host": parsed.netloc, "Content-Length": str(len(body)), "Connection": "close"})
    for key, value in headers.items():
        if not key or any(c in key for c in "\r\n :\0") or any(c in str(value) for c in "\r\n\0"):
            raise ValueError("Invalid HTTP header")
    packet = (method + " " + path + " HTTP/1.1\r\n" + "".join(k + ": " + str(v) + "\r\n" for k, v in headers.items()) + "\r\n").encode("latin-1") + body
    connection.send(packet)
    response = http.client.HTTPResponse(connection.sock, method=method)
    response.begin()
    raw = response.read(262145)
    truncated = len(raw) > 262144
    text = raw[:262144].decode("utf-8", errors="replace")
    output = {"status": response.status, "headers": list(response.getheaders()), "body": text, "truncated": truncated,
              "base64": base64.b64encode(raw[:262144]).decode()}
    try:
        output["json"] = json.loads(text)
    except (ValueError, RecursionError):
        pass
    return {"method": method, "url": url, "headers": headers, "body": body.decode("utf-8", errors="replace")}, output


class WebSocket:
    def __init__(self, connection, url, headers):
        self.connection = connection
        parsed = urlsplit(url)
        key = base64.b64encode(os.urandom(16)).decode()
        supplied = {k: str(v) for k, v in headers.items() if k.lower() not in {"host", "connection", "upgrade", "sec-websocket-key", "sec-websocket-version"}}
        supplied.update({"Host": parsed.netloc, "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13"})
        if any(any(c in k + v for c in "\r\n\0") for k, v in supplied.items()):
            raise ValueError("Invalid WebSocket headers")
        path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        wire = "GET " + path + " HTTP/1.1\r\n" + "".join(k + ": " + v + "\r\n" for k, v in supplied.items()) + "\r\n"
        connection.send(wire.encode("latin-1"))
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            if len(response) >= 65536:
                raise ValueError("Oversized WebSocket handshake")
            response.extend(connection.exact(1))
        lines = response.decode("latin-1").split("\r\n")
        self.status = int(lines[0].split()[1])
        response_headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                response_headers[k.lower()] = v.strip()
        self.evidence = {"status": self.status, "request": wire, "response": response.decode("latin-1")}
        if self.status != 101:
            return
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if response_headers.get("sec-websocket-accept") != expected or response_headers.get("upgrade", "").lower() != "websocket":
            raise ValueError("Invalid WebSocket upgrade")
        if response_headers.get("sec-websocket-extensions"):
            raise ValueError("Unrequested WebSocket extension")

    def send(self, text, opcode=1):
        if self.status != 101:
            raise ValueError("WebSocket handshake was not accepted")
        data = text.encode() if isinstance(text, str) else text
        if len(data) > 65536:
            raise ValueError("WebSocket payload limit exceeded")
        mask = os.urandom(4)
        length = bytes([0x80 | len(data)]) if len(data) < 126 else b"\xfe" + struct.pack("!H", len(data)) if len(data) <= 65535 else b"\xff" + struct.pack("!Q", len(data))
        self.connection.send(bytes([0x80 | opcode]) + length + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(data)))

    def receive(self):
        payload, first_opcode = bytearray(), None
        for _ in range(32):
            header = self.connection.exact(2)
            final, opcode = bool(header[0] & 0x80), header[0] & 15
            if header[0] & 0x70 or header[1] & 0x80:
                raise ValueError("Unsupported RSV or masked server frame")
            length = header[1] & 127
            if length == 126:
                length = struct.unpack("!H", self.connection.exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.connection.exact(8))[0]
            if length > 262144 - len(payload):
                raise ValueError("WebSocket message limit exceeded")
            data = self.connection.exact(length)
            if opcode in (8, 9, 10):
                if not final or length > 125:
                    raise ValueError("Invalid control frame")
                if opcode == 8:
                    return {"closed": True, "closeHex": data.hex()}
                if opcode == 9:
                    self.send(data, 10)
                continue
            if opcode in (1, 2) and first_opcode is None:
                first_opcode = opcode
            elif opcode != 0 or first_opcode is None:
                raise ValueError("Unexpected fragmented frame")
            payload.extend(data)
            if final:
                if first_opcode == 2:
                    return {"base64": base64.b64encode(payload).decode(), "bytes": len(payload)}
                text = payload.decode("utf-8")
                result = {"body": text}
                try:
                    result["json"] = json.loads(text)
                except (ValueError, RecursionError):
                    pass
                return result
        raise ValueError("WebSocket frame budget exhausted")


def run_scenario(request, grant=parent_grant):
    scenario = request["scenario"]
    budget = Budget(scenario["timeoutSeconds"], messages=400, bytes_limit=2_000_000)
    identities = {x["name"]: x for x in request.get("identities", [])}
    result = {"schema": 1, "engagementId": request["engagementId"], "runId": request["runId"], "testId": scenario["testId"],
              "target": scenario["id"], "backend": "recorded-scenario", "backendVersion": VERSION, "startedAt": now(),
              "execution": "completed", "security": "inconclusive", "confidence": "low", "severity": "information",
              "control": "not-run", "cleanup": "not-required", "evidence": [],
              "limitations": ["Assertions use tester-supplied application policy: " + scenario["policy"],
                              "Raw-client Origin acceptance is a lead; this runner does not reproduce browser SameSite/user-consent behavior."]}
    variables, connections, effects = {}, {}, []

    def expand(value):
        if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            name = value[2:-1]
            if name not in variables:
                raise ValueError("Missing extracted variable " + name)
            return variables[name]
        if isinstance(value, dict):
            return {k: expand(v) for k, v in value.items()}
        if isinstance(value, list):
            return [expand(v) for v in value]
        return value

    def steps(items, stage):
        observed = []
        for step in items:
            budget.check()
            url = str(expand(step["url"]))
            target = target_for(url)
            headers = {k: str(expand(v)) for k, v in step.get("headers", {}).items()}
            body = step.get("body", "")
            try:
                doc = expand(json.loads(body)) if body else None
            except ValueError:
                doc = None
            identity_name = step.get("identity", "")
            if identity_name:
                if identity_name != "absent" and identity_name not in identities:
                    raise ValueError("Missing identity " + identity_name)
                identity = identities.get(identity_name, {})
                parsed = urlsplit(url)
                origin = parsed._replace(path="", query="", fragment="", scheme="https" if target["transport"] == "tls" else "http").geturl()
                if identity and origin not in identity.get("origins", []):
                    raise Blocked("Identity is not associated with this origin: " + origin)
                header_names = {"authorization", "cookie", "x-auth-token", "x-api-key"} | {k.lower() for x in identities.values() for k in x.get("headers", {})}
                headers = {k: v for k, v in headers.items() if k.lower() not in header_names}
                headers.update(identity.get("headers", {}))
                query_names = {k for x in identities.values() for k in x.get("queryTokens", {})}
                query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k not in query_names]
                query.extend(identity.get("queryTokens", {}).items())
                url = parsed._replace(query=urlencode(query)).geturl()
                target = target_for(url)
                body_names = {k for x in identities.values() for k in x.get("bodyTokens", {})}
                if body_names:
                    if not isinstance(doc, dict):
                        raise ValueError("Body authentication requires a JSON object")
                    doc = {k: v for k, v in doc.items() if k not in body_names}
                    doc.update(identity.get("bodyTokens", {}))
            if doc is not None:
                body = json.dumps(doc)
            transport = step.get("transport", "http")
            name = step.get("connection", "main")
            wire_input = {"url": url, "transport": transport, "identity": identity_name, "body": body, "headers": headers}
            if transport == "http":
                connection = Connection(target, budget, grant)
                try:
                    wire_input, output = http_request(connection, step.get("method", "GET"), url, headers, body.encode())
                finally:
                    connection.close()
            elif transport == "ws-open":
                if name in connections:
                    raise ValueError("Close existing connection before reopening")
                connection = Connection(target, budget, grant)
                try:
                    ws = WebSocket(connection, url, headers)
                except BaseException:
                    connection.close()
                    raise
                connections[name] = ws
                output = ws.evidence
            else:
                ws = connections[name]
                # A different configured URL cannot authorize traffic on an existing connection.
                ws.connection.permit()
                if transport == "ws-send":
                    ws.send(body)
                    output = {"sent": True}
                elif transport == "ws-receive":
                    output = ws.receive()
                elif transport == "ws-close":
                    ws.send(b"\x03\xe8", 8)
                    ws.connection.close()
                    del connections[name]
                    output = {"closed": True}
                else:
                    raise ValueError("Unsupported scenario transport")
            evidence = {"stage": stage, "timestamp": now(), "input": wire_input, "output": output, "observation": step["id"]}
            result["evidence"].append(evidence)
            if output.get("truncated"):
                raise ValueError("Response evidence exceeded capture limit")
            status = step.get("expectStatus", [])
            if status and output.get("status") not in status:
                raise ValueError("Unexpected HTTP status at " + step["id"])
            for key, path in step.get("extract", {}).items():
                value = pointer(output, path)
                if value is None:
                    raise ValueError("Missing extraction " + path)
                variables[key] = value
            assertion = step.get("assertion")
            if assertion:
                matched = pointer(output, assertion["pointer"]) == expand(assertion["equals"])
                meaning = assertion.get("meaning", "protected-effect")
                result["evidence"].append({"stage": "effect" if stage == "case" else "control", "timestamp": now(),
                    "input": {"assertion": assertion, "step": step["id"]}, "output": {"matched": matched, "meaning": meaning}})
                if matched:
                    observed.append(meaning)
                elif stage == "control":
                    raise ValueError("Positive control assertion failed at " + step["id"])
            delay = scenario.get("intervalMs", 250) / 1000
            if time.monotonic() + delay >= budget.deadline:
                raise TimeoutError("Scenario duration budget exhausted")
            time.sleep(delay)
        return observed

    try:
        for case in scenario["cases"]:
            variables.clear()
            try:
                steps(scenario.get("setup", []), "setup")
                control = steps(scenario["control"], "control")
                if not any(x in control for x in ("protected-effect", "receiver-marker", "health-control")):
                    raise ValueError("Control did not demonstrate the protected effect")
                result["control"] = "passed"
                observed = steps(case["steps"], "case")
                if case.get("expectation", "rejected") == "rejected":
                    if any(x in observed for x in ("protected-effect", "receiver-marker")):
                        effects.append("policy-violation")
                    elif "explicit-rejection" in observed:
                        effects.append("demonstrated-rejection")
                    else:
                        effects.append("inconclusive")
                else:
                    effects.append("observed" if any(x in observed for x in ("protected-effect", "receiver-marker")) else "inconclusive")
            finally:
                try:
                    if scenario.get("cleanup"):
                        steps(scenario["cleanup"], "cleanup")
                        result["cleanup"] = "completed"
                except Exception as exc:
                    result["cleanup"] = "unconfirmed: " + str(exc)
                    raise
                finally:
                    for ws in connections.values():
                        ws.connection.close()
                    connections.clear()
        result["security"] = "policy-violation" if "policy-violation" in effects else "inconclusive" if "inconclusive" in effects else "demonstrated-rejection" if effects and all(x == "demonstrated-rejection" for x in effects) else "observed"
        if result["security"] == "policy-violation":
            result.update(confidence="medium", severity="medium")
    except Blocked as exc:
        result.update(execution="blocked", security="inconclusive")
        result["limitations"].append(str(exc))
    except (socket.timeout, TimeoutError) as exc:
        result.update(execution="timeout", security="inconclusive")
        result["limitations"].append(str(exc))
    except Exception as exc:
        result.update(execution="partial", security="inconclusive")
        result["limitations"].append(str(exc))
    result["endedAt"] = now()
    return result


def main():
    request = json.loads(sys.stdin.readline(2_000_001))
    if "scenario" in request:
        scenario = request["scenario"]
        total = len(scenario.get("setup", [])) + len(scenario["control"]) + sum(len(x["steps"]) for x in scenario["cases"]) + len(scenario.get("cleanup", []))
        if not 5 <= scenario["timeoutSeconds"] <= 300 or not 1 <= len(scenario["cases"]) <= 20 or total > 100:
            raise ValueError("Scenario exceeds limits")
        result = json.dumps({"result": run_scenario(request)}, ensure_ascii=True)
        if len(result) > MAX_OUTPUT:
            raise ValueError("Evidence output limit exceeded")
        print(result, flush=True)
        return
    if request.get("testId") not in {"TRN-01", "TRN-02", "TRN-04", "TRN-05", "TRN-07"}:
        raise ValueError("Unsupported test ID")
    if request["target"]["scheme"] not in {"stun", "stuns", "turn", "turns"}:
        raise ValueError("This adapter requires a STUN/TURN listener")
    if request["testId"] != "TRN-01" and request["target"]["scheme"] not in {"turn", "turns"}:
        raise ValueError("Allocation tests require a TURN listener")
    if not 15 <= request.get("timeoutSeconds", 60) <= 300 or len(request.get("credentials", [])) > 6:
        raise ValueError("Invalid runner budgets")
    result = json.dumps({"result": run_turn(request)}, ensure_ascii=True)
    if len(result) > MAX_OUTPUT:
        raise ValueError("Evidence output limit exceeded")
    print(result, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"error": str(error)}), flush=True)
        sys.exit(1)
