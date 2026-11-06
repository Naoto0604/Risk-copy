import unittest
from pathlib import Path

from engine.observations import Observation
from engine.rule_runner import run
from engine.rules import load_rules_from_dir

URL = "https://example.test/"

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "explore"

SATISFIED = frozenset({"proof", "consent"})


def repo(remotes=None, exposed=True):
    return Observation.ok(
        "explore_repo", URL,
        {
            "paths": [],
            "exposed": exposed,
            "head_exposed": exposed,
            "config_exposed": exposed,
            "listing_exposed": exposed,
            "head_branch": "refs/heads/main" if exposed else None,
            "head_detached": None,
            "remotes": remotes or [],
            "providers": [],
            "skipped": [],
            "robots": "unavailable",
            "truncated": False,
            "truncated_reason": None,
        },
    )


def discover(found=(), gated=()):
    return Observation.ok(
        "explore_discover", URL,
        {
            "probes": [],
            "found": list(found) + list(gated),
            "found_paths": list(found),
            "gated_paths": list(gated),
            "skipped": [],
            "robots": "unavailable",
            "truncated": False,
            "truncated_reason": None,
        },
    )


def ids_of(findings):
    return {finding.rule_id for finding in findings}


def run_with(observations, satisfied=SATISFIED):
    return run(load_rules_from_dir(RULES_DIR), observations, satisfied=satisfied)


class TestLoading(unittest.TestCase):

    def test_directory_loads(self):
        self.assertGreaterEqual(len(load_rules_from_dir(RULES_DIR)), 8)

    def test_every_rule_uses_one_collector(self):
        for rule in load_rules_from_dir(RULES_DIR):
            self.assertEqual(len(rule.collectors), 1)


class TestRepo(unittest.TestCase):

    def test_head_exposure_is_reported(self):
        normal, _low = run_with([repo()])
        self.assertIn("explore.git-head-exposed", ids_of(normal))

    def test_config_exposure_is_reported(self):
        normal, _low = run_with([repo()])
        self.assertIn("explore.git-config-exposed", ids_of(normal))

    def test_no_exposure_is_not_reported(self):
        normal, _low = run_with([repo(exposed=False)])
        self.assertNotIn("explore.git-head-exposed", ids_of(normal))

    def test_remote_is_low_confidence(self):
        remotes = [{"name": "origin", "url": "https://github.com/a/b.git",
                    "host": "github.com", "provider": "github"}]
        _normal, low = run_with([repo(remotes=remotes)])
        self.assertIn("explore.git-remote-visible", ids_of(low))


class TestDiscover(unittest.TestCase):

    def test_env_exposure_is_low_confidence(self):
        _normal, low = run_with([discover(found=["/.env"])])
        self.assertIn("explore.env-exposed", ids_of(low))

    def test_admin_found_is_low_confidence(self):
        _normal, low = run_with([discover(found=["/admin"])])
        self.assertIn("explore.admin-reachable", ids_of(low))

    def test_admin_gated_is_low_confidence(self):
        _normal, low = run_with([discover(gated=["/admin"])])
        self.assertIn("explore.admin-gated", ids_of(low))

    def test_wp_admin_is_low_confidence(self):
        _normal, low = run_with([discover(found=["/wp-admin/"])])
        self.assertIn("explore.wp-admin-reachable", ids_of(low))

    def test_server_status_is_reported(self):
        normal, _low = run_with([discover(found=["/server-status"])])
        self.assertIn("explore.server-status", ids_of(normal))

    def test_empty_discovery_reports_nothing(self):
        normal, low = run_with([discover()])
        self.assertEqual(normal, [])
        self.assertEqual(low, [])


class TestGate(unittest.TestCase):

    def test_no_findings_without_requirements(self):
        normal, low = run_with([repo()], satisfied=frozenset())
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_subject_is_the_url(self):
        normal, _low = run_with([discover(found=["/server-status"])])
        self.assertTrue(all(finding.subject == URL for finding in normal))


if __name__ == "__main__":
    unittest.main()