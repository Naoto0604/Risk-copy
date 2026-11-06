import unittest
from pathlib import Path

from engine.observations import Observation
from engine.rule_runner import run
from engine.rules import load_rules_from_dir

URL = "https://example.test/"

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "headers"

ALL_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "content-security-policy-report-only": None,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": None,
    "cache-control": "no-store",
    "access-control-allow-origin": None,
    "access-control-allow-credentials": None,
}


def observation(**overrides):
    headers = dict(ALL_HEADERS)
    headers.update(overrides)
    return Observation.ok("http_headers", URL, {"headers": headers, "downgraded": False})


def ids_of(findings):
    return {finding.rule_id for finding in findings}


class TestLoading(unittest.TestCase):

    def test_directory_loads(self):
        self.assertGreaterEqual(len(load_rules_from_dir(RULES_DIR)), 7)

    def test_every_rule_requires_proof_and_consent(self):
        for rule in load_rules_from_dir(RULES_DIR):
            self.assertEqual(set(rule.requires), {"proof", "consent"})

    def test_every_rule_has_confidence(self):
        for rule in load_rules_from_dir(RULES_DIR):
            self.assertIn(rule.confidence, ("low", "medium", "high"))

    def test_every_rule_uses_one_collector(self):
        for rule in load_rules_from_dir(RULES_DIR):
            self.assertEqual(rule.collectors, ("http_headers",))


class TestEvaluation(unittest.TestCase):

    def run_with(self, observations, satisfied=frozenset({"proof", "consent"})):
        return run(load_rules_from_dir(RULES_DIR), observations, satisfied=satisfied)

    def test_full_headers_produce_no_findings(self):
        normal, low = self.run_with([observation()])
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_missing_hsts_is_reported(self):
        normal, _low = self.run_with([observation(**{"strict-transport-security": None})])
        self.assertIn("headers.hsts-missing", ids_of(normal))

    def test_short_max_age_is_low_confidence(self):
        _normal, low = self.run_with([observation(**{"strict-transport-security": "max-age=600"})])
        self.assertIn("headers.hsts-short-max-age", ids_of(low))

    def test_long_max_age_is_not_reported(self):
        _normal, low = self.run_with([observation()])
        self.assertNotIn("headers.hsts-short-max-age", ids_of(low))

    def test_missing_csp_is_reported(self):
        normal, _low = self.run_with([observation(**{"content-security-policy": None})])
        self.assertIn("headers.csp-missing", ids_of(normal))

    def test_report_only_suppresses_csp_missing(self):
        normal, _low = self.run_with([observation(**{
            "content-security-policy": None,
            "content-security-policy-report-only": "default-src 'self'",
        })])
        self.assertNotIn("headers.csp-missing", ids_of(normal))

    def test_unsafe_inline_is_reported(self):
        normal, _low = self.run_with([observation(**{
            "content-security-policy": "script-src 'self' 'unsafe-inline'",
        })])
        self.assertIn("headers.csp-unsafe-inline", ids_of(normal))

    def test_downgrade_is_reported(self):
        degraded = Observation.ok("http_headers", URL, {"headers": ALL_HEADERS, "downgraded": True})
        normal, _low = self.run_with([degraded])
        self.assertIn("headers.transport-downgraded", ids_of(normal))

    def test_no_findings_without_requirements(self):
        normal, low = self.run_with([observation()], satisfied=frozenset())
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_subject_is_the_url(self):
        normal, _low = self.run_with([observation(**{"x-frame-options": None})])
        self.assertTrue(all(finding.subject == URL for finding in normal))


if __name__ == "__main__":
    unittest.main()