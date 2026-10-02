"""Bundled TLS-over-TCP runner. Burp owns target authorization and process lifetime."""
import importlib.metadata
import json
import re
import sys
from datetime import datetime, timezone

SSLYZE_VERSION = "6.3.1"
BASE_CHECKS = (
    "certificate_info", "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
    "tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites",
    "tls_1_3_cipher_suites", "tls_compression", "tls_fallback_scsv", "elliptic_curves",
)
EXTRA_CHECKS = ("heartbleed", "openssl_ccs_injection", "robot", "session_renegotiation")


def validate_request(request):
    host, port = request.get("hostname"), request.get("port")
    if not isinstance(host, str) or not 1 <= len(host) <= 253 or re.search(r"[\s/@?#;\\]", host):
        raise ValueError("Invalid TLS hostname")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid TLS port")
    if type(request.get("vulnerabilityChecks", False)) is not bool:
        raise ValueError("vulnerabilityChecks must be boolean")
    return host, port


def summarize(raw):
    """Keep explicit failed/skipped checks separate from successful negative results."""
    checks, findings = [], []
    attempts = raw.get("scan_result") or {}
    for name, attempt in attempts.items():
        state = attempt.get("status", "UNKNOWN").lower()
        if state == "not_scheduled":
            continue
        result = attempt.get("result") or {}
        summary = name.replace("_", " ") + ": " + state
        if state == "completed" and name.endswith("cipher_suites"):
            accepted = [item["cipher_suite"]["name"] for item in result.get("accepted_cipher_suites", [])]
            summary += "; " + str(len(accepted)) + " accepted cipher suite(s)"
            if accepted and name in BASE_CHECKS[1:5]:
                findings.append({"level": "finding", "check": name, "text": name.replace("_cipher_suites", "").replace("_", " ") + " accepted by the listener"})
            weak = [cipher for cipher in accepted if re.search(r"NULL|EXPORT|RC4|3DES|(?:^|_)DES(?:_|$)|anon|ADH|AECDH", cipher, re.I)]
            if weak:
                findings.append({"level": "finding", "check": name, "text": "Weak cipher suite(s) accepted: " + ", ".join(weak)})
        if state == "completed" and name == "certificate_info":
            deployments = result.get("certificate_deployments", [])
            summary += "; " + str(len(deployments)) + " certificate deployment(s)"
            for deployment in deployments:
                paths = deployment.get("path_validation_results", [])
                if paths and not any(path.get("was_validation_successful") for path in paths):
                    findings.append({"level": "warn", "text": "Certificate validation failed against every tested SSLyze trust store; inspect path validation errors for trust, hostname or validity issues"})
                if deployment.get("verified_chain_has_sha1_signature") is True:
                    findings.append({"level": "warn", "text": "Verified certificate chain contains a SHA-1 signature"})
        positive_flags = {
            "tls_compression": ("supports_compression", "TLS compression supported (CRIME precondition)"),
            "heartbleed": ("is_vulnerable_to_heartbleed", "SSLyze reports Heartbleed vulnerability"),
            "openssl_ccs_injection": ("is_vulnerable_to_ccs_injection", "SSLyze reports OpenSSL CCS injection vulnerability"),
        }
        if state == "completed" and name in positive_flags:
            flag, text = positive_flags[name]
            if result.get(flag) is True:
                findings.append({"level": "finding", "text": text})
        if state == "completed" and name == "robot" and str(result.get("robot_result", "")).startswith("VULNERABLE"):
            findings.append({"level": "finding", "text": "SSLyze reports ROBOT: " + result["robot_result"]})
        if state == "completed" and name == "session_renegotiation" and result.get("supports_secure_renegotiation") is False:
            findings.append({"level": "warn", "text": "Secure renegotiation not supported; review the renegotiation result"})
        if state == "error":
            summary += "; " + str(attempt.get("error_reason") or "unknown error")
        checks.append({"name": name, "status": state, "summary": summary})
    complete = bool(checks) and all(check["status"] == "completed" for check in checks)
    status = "completed" if complete and raw.get("scan_status") == "COMPLETED" else "partial"
    if raw.get("scan_result") is None:
        status = "failed"
    return {"status": status, "checks": checks, "findings": findings, "raw": raw}


def scan(request):
    host, port = validate_request(request)
    from sslyze import Scanner, ScanCommand, ServerNetworkLocation, ServerNetworkConfiguration, ServerScanRequest, ServerScanResultAsJson

    names = BASE_CHECKS + (EXTRA_CHECKS if request.get("vulnerabilityChecks") else ())
    commands = {ScanCommand(name) for name in names}
    scanner = Scanner(per_server_concurrent_connections_limit=2, concurrent_server_scans_limit=1)
    scanner.queue_scans([ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=host, port=port),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=host, network_timeout=5, network_max_retries=0),
        scan_commands=commands,
    )])
    results = list(scanner.get_results())
    if len(results) != 1:
        raise RuntimeError("Expected exactly one server result")
    raw = ServerScanResultAsJson.model_validate(results[0]).model_dump(mode="json")
    result = summarize(raw)
    # Certificate validity/key sizes are evidence distinct from trust-store validation.
    cert_attempt = results[0].scan_result.certificate_info if results[0].scan_result else None
    if cert_attempt and cert_attempt.result:
        for deployment in cert_attempt.result.certificate_deployments:
            leaf = deployment.received_certificate_chain[0]
            now = datetime.now(timezone.utc)
            if leaf.not_valid_after_utc < now or leaf.not_valid_before_utc > now:
                result["findings"].append({"level": "warn", "text": "Listener certificate is outside its validity period"})
            key = leaf.public_key()
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            if (isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048) or (isinstance(key, ec.EllipticCurvePublicKey) and key.key_size < 256):
                result["findings"].append({"level": "warn", "text": "Listener certificate has a weak public key: " + str(key.key_size) + " bits"})
    result.update(schema=1, engine="SSLyze " + SSLYZE_VERSION, hostname=host, port=port)
    return result


def main():
    try:
        version = importlib.metadata.version("sslyze")
        if version != SSLYZE_VERSION:
            raise RuntimeError("Expected SSLyze " + SSLYZE_VERSION + "; use Setup TLS runner")
        if sys.argv[1:] == ["--check"]:
            import sslyze  # Verify native dependencies load, without connecting anywhere.
            output = {"ready": True, "engine": "SSLyze " + version, "python": sys.version.split()[0]}
        elif not sys.argv[1:]:
            request = json.loads(sys.stdin.read(8193))
            output = scan(request)
        else:
            raise ValueError("Unsupported runner argument")
        print(json.dumps(output, ensure_ascii=True), flush=True)
        return 0
    except Exception as error:
        print(json.dumps({"status": "failed", "ready": False, "error": str(error)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
