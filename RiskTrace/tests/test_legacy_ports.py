import unittest
from unittest import mock

from engine import legacy_ports
from engine.observations import Observation

URL = "https://example.test/"


def entry(port, state="open", scope="PUBLIC", peer="203.0.113.9", banner=None):
    return {"port": port, "state": state, "banner": banner, "peer": peer,
            "scope": scope, "error": None, "conventional": None}


def ports_observation(entries):
    return Observation.ok("ports", "example.test", {"ports": entries})


def tls_observation(verification="FAILED"):
    return Observation.ok("tls", URL, {
        "verification": verification,
        "verification_error": "certificate has expired",
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "certificate": {},
    })


class TestValidation(unittest.TestCase):

    def test_bad_scheme_raises(self):
        with self.assertRaises(ValueError):
            legacy_ports.check_web_ports("ftp://example.test/")

    def test_credentials_raise(self):
        with self.assertRaises(ValueError):
            legacy_ports.check_web_ports("https://u:p@example.test/")


class TestSeverity(unittest.TestCase):

    def test_loopback_is_info(self):
        self.assertEqual(legacy_ports._severity_for(3306, "LOOPBACK"), "INFO")

    def test_sensitive_public_is_low(self):
        self.assertEqual(legacy_ports._severity_for(3306, "PUBLIC"), "LOW")

    def test_development_public_is_low(self):
        self.assertEqual(legacy_ports._severity_for(3000, "PUBLIC"), "LOW")

    def test_plain_public_is_info(self):
        self.assertEqual(legacy_ports._severity_for(8080, "PUBLIC"), "INFO")


class TestEvidence(unittest.TestCase):

    def test_evidence_carries_port_and_scope(self):
        text = legacy_ports._evidence(entry(3306), URL)
        self.assertIn("Port: 3306", text)
        self.assertIn("Network scope: PUBLIC", text)

    def test_banner_is_marked_unverified(self):
        text = legacy_ports._evidence(entry(22, banner="SSH-2.0-OpenSSH_9"), URL)
        self.assertIn("Banner (unverified): SSH-2.0-OpenSSH_9", text)


class TestFindings(unittest.TestCase):

    def run_with(self, entries, tls=None):
        with mock.patch.object(legacy_ports.scan, "collect",
                               return_value=ports_observation(entries)):
            with mock.patch.object(legacy_ports.tls, "collect",
                                   return_value=tls or tls_observation("VERIFIED")):
                return legacy_ports.check_web_ports(URL)

    def test_open_port_becomes_a_finding(self):
        findings = self.run_with([entry(3306)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "PORT_SCAN")
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertIn("3306", findings[0]["title"])

    def test_closed_port_is_skipped(self):
        findings = self.run_with([entry(3306, state="closed", peer=None)])
        self.assertEqual([f["type"] for f in findings], ["PORT_SCAN"])
        self.assertEqual(findings[0]["subtype"], "NO_CONFIGURED_PORT_DETECTED")

    def test_no_open_port_reports_the_gap(self):
        findings = self.run_with([])
        self.assertEqual(findings[0]["subtype"], "NO_CONFIGURED_PORT_DETECTED")
        self.assertEqual(findings[0]["severity"], "INFO")

    def test_loopback_port_is_info(self):
        findings = self.run_with([entry(3306, scope="LOOPBACK", peer="127.0.0.1")])
        self.assertEqual(findings[0]["severity"], "INFO")

    def test_tls_failure_adds_a_finding(self):
        findings = self.run_with([entry(443)], tls=tls_observation())
        self.assertEqual([f["type"] for f in findings], ["PORT_SCAN", "TLS"])
        self.assertEqual(findings[1]["severity"], "MEDIUM")

    def test_verified_tls_adds_nothing(self):
        findings = self.run_with([entry(443)], tls=tls_observation("VERIFIED"))
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()