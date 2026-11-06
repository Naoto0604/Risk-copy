import unittest
from pathlib import Path

from engine.observations import Observation
from engine.rule_runner import run
from engine.rules import load_rules_from_dir

DOMAIN = "example.test"

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "dns"

SATISFIED = frozenset({"proof", "consent"})


def observation(spf_present=True, multiple=False, policy="-all",
                dmarc_present=True, dmarc_policy="reject", dkim_resolved=True):
    return Observation.ok(
        "dns", DOMAIN,
        {
            "domain": DOMAIN,
            "spf": {"present": spf_present, "count": 1, "multiple": multiple, "policy": policy},
            "dmarc": {"present": dmarc_present, "policy": dmarc_policy},
            "dkim": {"selectors_found": ["default"], "selectors_tried": ["default"],
                     "resolved": dkim_resolved},
        },
    )


def ids_of(findings):
    return {finding.rule_id for finding in findings}


def run_with(observations, satisfied=SATISFIED):
    return run(load_rules_from_dir(RULES_DIR), observations, satisfied=satisfied)


class TestLoading(unittest.TestCase):

    def test_directory_loads(self):
        self.assertGreaterEqual(len(load_rules_from_dir(RULES_DIR)), 5)


class TestSpf(unittest.TestCase):

    def test_missing_spf_is_reported(self):
        normal, _low = run_with([observation(spf_present=False)])
        self.assertIn("dns.spf-missing", ids_of(normal))

    def test_present_spf_is_not_reported(self):
        normal, _low = run_with([observation()])
        self.assertNotIn("dns.spf-missing", ids_of(normal))

    def test_multiple_spf_is_reported(self):
        normal, _low = run_with([observation(multiple=True)])
        self.assertIn("dns.spf-multiple", ids_of(normal))

    def test_plus_all_is_low_confidence(self):
        _normal, low = run_with([observation(policy="+all")])
        self.assertIn("dns.spf-all-plus", ids_of(low))

    def test_hardfail_is_not_reported(self):
        _normal, low = run_with([observation(policy="-all")])
        self.assertNotIn("dns.spf-all-plus", ids_of(low))


class TestDmarc(unittest.TestCase):

    def test_missing_dmarc_is_reported(self):
        normal, _low = run_with([observation(dmarc_present=False)])
        self.assertIn("dns.dmarc-missing", ids_of(normal))

    def test_policy_none_is_reported(self):
        normal, _low = run_with([observation(dmarc_policy="none")])
        self.assertIn("dns.dmarc-none", ids_of(normal))

    def test_policy_reject_is_not_reported(self):
        normal, _low = run_with([observation(dmarc_policy="reject")])
        self.assertNotIn("dns.dmarc-none", ids_of(normal))

    def test_missing_policy_is_not_reported_as_none(self):
        normal, _low = run_with([observation(dmarc_policy=None)])
        self.assertNotIn("dns.dmarc-none", ids_of(normal))


class TestGate(unittest.TestCase):

    def test_no_findings_without_requirements(self):
        normal, low = run_with([observation(spf_present=False)], satisfied=frozenset())
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_subject_is_the_domain(self):
        normal, _low = run_with([observation(spf_present=False)])
        self.assertTrue(all(finding.subject == DOMAIN for finding in normal))


if __name__ == "__main__":
    unittest.main()