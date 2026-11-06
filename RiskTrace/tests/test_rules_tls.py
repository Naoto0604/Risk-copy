import unittest
from pathlib import Path

from engine.observations import Observation
from engine.rule_runner import run
from engine.rules import load_rules_from_dir

URL = "https://example.test/"

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "tls"

SATISFIED = frozenset({"proof", "consent"})


def certificate(days=300):
    return {
        "present": True,
        "der_length": 1200,
        "subject_cn": "example.test",
        "issuer_cn": "Test CA",
        "issuer_org": "Test Org",
        "san": ["example.test"],
        "not_before": "Jan  1 00:00:00 2026 GMT",
        "not_after": "Jan  1 00:00:00 2027 GMT",
        "days_until_expiry": days,
    }


def observation(verification="VERIFIED", protocol="TLSv1.3", cipher_bits=128, days=300):
    return Observation.ok(
        "tls", URL,
        {
            "verification": verification,
            "verification_error": None,
            "retried_without_verification": verification == "FAILED",
            "protocol": protocol,
            "cipher": "TLS_AES_128_GCM_SHA256",
            "cipher_bits": cipher_bits,
            "certificate": certificate(days),
            "port": 443,
        },
    )


def ids_of(findings):
    return {finding.rule_id for finding in findings}


def run_with(observations, satisfied=SATISFIED):
    return run(load_rules_from_dir(RULES_DIR), observations, satisfied=satisfied)


class TestLoading(unittest.TestCase):

    def test_directory_loads(self):
        self.assertGreaterEqual(len(load_rules_from_dir(RULES_DIR)), 4)

    def test_every_rule_uses_one_collector(self):
        for rule in load_rules_from_dir(RULES_DIR):
            self.assertEqual(rule.collectors, ("tls",))


class TestVerification(unittest.TestCase):

    def test_failed_verification_is_high(self):
        normal, _low = run_with([observation(verification="FAILED")])
        finding = next(f for f in normal if f.rule_id == "tls.verification-failed")
        self.assertEqual(finding.severity, "HIGH")

    def test_verified_is_not_reported(self):
        normal, _low = run_with([observation()])
        self.assertNotIn("tls.verification-failed", ids_of(normal))


class TestExpiry(unittest.TestCase):

    def test_expired_is_reported(self):
        normal, _low = run_with([observation(days=-1)])
        self.assertIn("tls.expired", ids_of(normal))

    def test_expiring_soon_is_reported(self):
        normal, _low = run_with([observation(days=10)])
        self.assertIn("tls.expiring-soon", ids_of(normal))

    def test_healthy_expiry_is_not_reported(self):
        normal, _low = run_with([observation(days=200)])
        self.assertNotIn("tls.expiring-soon", ids_of(normal))
        self.assertNotIn("tls.expired", ids_of(normal))

    def test_missing_days_does_not_report(self):
        broken = Observation.ok("tls", URL, {"verification": "VERIFIED", "certificate": {}})
        normal, _low = run_with([broken])
        self.assertNotIn("tls.expiring-soon", ids_of(normal))


class TestProtocol(unittest.TestCase):

    def test_tls10_is_reported(self):
        normal, _low = run_with([observation(protocol="TLSv1")])
        self.assertIn("tls.legacy-protocol", ids_of(normal))

    def test_tls12_is_not_reported(self):
        normal, _low = run_with([observation(protocol="TLSv1.2")])
        self.assertNotIn("tls.legacy-protocol", ids_of(normal))


class TestCipher(unittest.TestCase):

    def test_short_key_is_reported(self):
        normal, _low = run_with([observation(cipher_bits=64)])
        self.assertIn("tls.weak-cipher", ids_of(normal))

    def test_128_bit_is_not_reported(self):
        normal, _low = run_with([observation(cipher_bits=128)])
        self.assertNotIn("tls.weak-cipher", ids_of(normal))


class TestGate(unittest.TestCase):

    def test_no_findings_without_requirements(self):
        normal, low = run_with([observation(verification="FAILED")], satisfied=frozenset())
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_skipped_observation_is_ignored(self):
        skipped = Observation.skipped("tls", URL, "https ではない")
        normal, low = run_with([skipped])
        self.assertEqual(normal, [])
        self.assertEqual(low, [])


if __name__ == "__main__":
    unittest.main()