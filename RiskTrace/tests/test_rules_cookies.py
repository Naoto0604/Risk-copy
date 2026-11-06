import unittest
from pathlib import Path

from engine.observations import Observation
from engine.rule_runner import run
from engine.rules import load_rules_from_dir

URL = "https://example.test/"

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "cookies"

SATISFIED = frozenset({"proof", "consent"})


def cookie(secure=True, httponly=True, samesite="lax"):
    return {
        "id": "Cookie #1",
        "attributes": {
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "domain": None,
            "path": True,
            "max-age": False,
            "expires": False,
            "partitioned": False,
        },
        "samesite": samesite,
        "samesite_valid": samesite in ("lax", "strict", "none") if samesite else None,
    }


def observation(*cookies, secure_transport=True):
    return Observation.ok(
        "http_cookies", URL,
        {"cookies": list(cookies), "count": len(cookies),
         "secure_transport": secure_transport, "downgraded": False},
    )


def ids_of(findings):
    return {finding.rule_id for finding in findings}


def run_with(observations, satisfied=SATISFIED):
    return run(load_rules_from_dir(RULES_DIR), observations, satisfied=satisfied)


class TestLoading(unittest.TestCase):

    def test_directory_loads(self):
        self.assertGreaterEqual(len(load_rules_from_dir(RULES_DIR)), 5)

    def test_every_rule_uses_one_collector(self):
        for rule in load_rules_from_dir(RULES_DIR):
            self.assertEqual(rule.collectors, ("http_cookies",))


class TestSecure(unittest.TestCase):

    def test_secure_missing_is_reported(self):
        normal, _low = run_with([observation(cookie(secure=False))])
        self.assertIn("cookies.secure-missing", ids_of(normal))

    def test_secure_missing_needs_https(self):
        normal, _low = run_with([observation(cookie(secure=False), secure_transport=False)])
        self.assertNotIn("cookies.secure-missing", ids_of(normal))

    def test_all_secure_is_not_reported(self):
        normal, _low = run_with([observation(cookie(secure=True))])
        self.assertNotIn("cookies.secure-missing", ids_of(normal))

    def test_one_offending_cookie_is_enough(self):
        normal, _low = run_with([observation(cookie(secure=True), cookie(secure=False))])
        self.assertIn("cookies.secure-missing", ids_of(normal))


class TestHttpOnly(unittest.TestCase):

    def test_httponly_missing_is_reported(self):
        normal, _low = run_with([observation(cookie(httponly=False))])
        self.assertIn("cookies.httponly-missing", ids_of(normal))

    def test_all_httponly_is_not_reported(self):
        normal, _low = run_with([observation(cookie(httponly=True))])
        self.assertNotIn("cookies.httponly-missing", ids_of(normal))


class TestSameSite(unittest.TestCase):

    def test_missing_samesite_is_reported(self):
        normal, _low = run_with([observation(cookie(samesite=None))])
        self.assertIn("cookies.samesite-missing", ids_of(normal))

    def test_explicit_samesite_is_not_reported(self):
        normal, _low = run_with([observation(cookie(samesite="lax"))])
        self.assertNotIn("cookies.samesite-missing", ids_of(normal))

    def test_samesite_none_is_low_confidence(self):
        _normal, low = run_with([observation(cookie(samesite="none"))])
        self.assertIn("cookies.samesite-none", ids_of(low))


class TestTransport(unittest.TestCase):

    def test_over_http_is_reported(self):
        normal, _low = run_with([observation(cookie(), secure_transport=False)])
        self.assertIn("cookies.over-http", ids_of(normal))

    def test_over_https_is_not_reported(self):
        normal, _low = run_with([observation(cookie())])
        self.assertNotIn("cookies.over-http", ids_of(normal))


class TestGate(unittest.TestCase):

    def test_no_findings_without_requirements(self):
        normal, low = run_with([observation(cookie(secure=False))], satisfied=frozenset())
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_subject_is_the_url(self):
        normal, _low = run_with([observation(cookie(secure=False))])
        self.assertTrue(all(finding.subject == URL for finding in normal))


if __name__ == "__main__":
    unittest.main()