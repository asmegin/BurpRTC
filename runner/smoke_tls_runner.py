"""Exercise real SSLyze against an ephemeral localhost TLS listener; no external target."""
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    with tempfile.TemporaryDirectory(prefix="webrtc-tls-smoke-") as temp:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1)).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).sign(key, hashes.SHA256()))
        certpath, keypath = Path(temp, "cert.pem"), Path(temp, "key.pem")
        certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certpath, keypath)
        listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(128); listener.settimeout(.2)
        port = listener.getsockname()[1]
        stopped = threading.Event()
        application_data = []

        def handle(sock):
            try:
                sock.settimeout(2)
                with context.wrap_socket(sock, server_side=True) as secure:
                    data = secure.recv(4096)
                    if data:
                        application_data.append(data)
            except (OSError, ssl.SSLError):
                sock.close()

        def serve():
            while not stopped.is_set():
                try:
                    sock, _ = listener.accept()
                    threading.Thread(target=handle, args=(sock,), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        thread = threading.Thread(target=serve, daemon=True); thread.start()
        try:
            for extras in (False, True):
                process = subprocess.run([sys.executable, "-I", "-u", str(Path(__file__).with_name("tls_runner.py"))],
                    input=json.dumps({"hostname": "localhost", "port": port, "vulnerabilityChecks": extras}),
                    text=True, capture_output=True, timeout=120)
                assert process.returncode == 0, process.stdout + process.stderr
                result = json.loads(process.stdout)
                assert result["schema"] == 1 and result["hostname"] == "localhost" and result["port"] == port
                assert result["status"] in ("completed", "partial"), result
                assert len(result["checks"]) == (14 if extras else 10), result["checks"]
                attempts = result["raw"]["scan_result"]
                assert attempts["tls_1_2_cipher_suites"]["result"]["accepted_cipher_suites"]
                assert attempts["tls_1_3_cipher_suites"]["result"]["accepted_cipher_suites"]
                assert not attempts["tls_1_0_cipher_suites"]["result"]["accepted_cipher_suites"]
                assert any("Certificate validation failed" in f["text"] for f in result["findings"])
                assert not any(f["level"] == "finding" for f in result["findings"]), result["findings"]
                print(f"Local TLS smoke ({'extra' if extras else 'base'}): {result['status']}, {len(result['checks'])} checks; TLS 1.2/1.3 and untrusted certificate observed")
            assert not any(data.startswith((b"GET ", b"HEAD ", b"POST ")) for data in application_data), application_data
            print("No HTTP requests sent to the TLS listener")
        finally:
            stopped.set(); listener.close(); thread.join(2)


if __name__ == "__main__":
    main()
