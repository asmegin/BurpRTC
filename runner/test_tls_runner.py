import unittest
from tls_runner import BASE_CHECKS, EXTRA_CHECKS, summarize, validate_request


class TlsRunnerTests(unittest.TestCase):
    def test_strict_input(self):
        self.assertEqual(("::1", 5349), validate_request({"hostname": "::1", "port": 5349}))
        for request in ({"hostname": "host/path", "port": 443}, {"hostname": "host", "port": True},
                        {"hostname": "host", "port": 0}, {"hostname": "host", "port": 443, "vulnerabilityChecks": "true"}):
            with self.assertRaises(ValueError):
                validate_request(request)

    def test_no_http_or_unrequested_vulnerability_commands(self):
        self.assertNotIn("http_headers", BASE_CHECKS + EXTRA_CHECKS)
        self.assertFalse(set(BASE_CHECKS) & set(EXTRA_CHECKS))

    def test_weak_protocol_and_cipher_are_positive_evidence(self):
        result = summarize({"scan_status": "COMPLETED", "scan_result": {
            "tls_1_0_cipher_suites": {"status": "COMPLETED", "result": {
                "accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_RSA_WITH_RC4_128_SHA"}}]}},
            "tls_compression": {"status": "COMPLETED", "result": {"supports_compression": False}},
            "robot": {"status": "NOT_SCHEDULED"}}})
        self.assertEqual("completed", result["status"])
        self.assertEqual(2, len(result["findings"]))
        self.assertTrue(all(f["check"] == "tls_1_0_cipher_suites" for f in result["findings"]))
        self.assertEqual(2, len(result["checks"]))

    def test_errors_never_become_negative_or_passed_findings(self):
        raw = {"scan_status": "COMPLETED", "scan_result": {
            "heartbleed": {"status": "ERROR", "error_reason": "TIMEOUT", "result": None},
            "robot": {"status": "COMPLETED", "result": {"robot_result": "UNKNOWN_INCONSISTENT_RESULTS"}}}}
        result = summarize(raw)
        self.assertEqual("partial", result["status"])
        self.assertEqual([], result["findings"])
        self.assertIn("TIMEOUT", result["checks"][0]["summary"])
        self.assertEqual("failed", summarize({"scan_status": "ERROR", "scan_result": None})["status"])

    def test_certificate_and_vulnerability_evidence(self):
        result = summarize({"scan_status": "COMPLETED", "scan_result": {
            "certificate_info": {"status": "COMPLETED", "result": {"certificate_deployments": [{
                "path_validation_results": [{"was_validation_successful": False}],
                "verified_chain_has_sha1_signature": True}]}},
            "heartbleed": {"status": "COMPLETED", "result": {"is_vulnerable_to_heartbleed": True}},
            "openssl_ccs_injection": {"status": "COMPLETED", "result": {"is_vulnerable_to_ccs_injection": True}},
            "robot": {"status": "COMPLETED", "result": {"robot_result": "VULNERABLE_STRONG_ORACLE"}}}})
        self.assertEqual(2, sum(f["level"] == "warn" for f in result["findings"]))
        self.assertEqual(3, sum(f["level"] == "finding" for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
