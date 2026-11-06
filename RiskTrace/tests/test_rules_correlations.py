import unittest
from pathlib import Path

from engine.correlation import CORRELATION_PREFIX, load_correlations_from_dir, run
from engine.observations import Observation
from engine.rule_runner import MISSING, ObservationIndex, _walk

TARGET = "https://example.test/"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "correlations"
SATISFIED = ["proof", "consent"]

BAAS = "correlation.baas-wildcard-cors"
ADMIN = "correlation.admin-without-auth-challenge"
ASSETS = "correlation.external-asset-without-sri-and-csp"


def index(*observations):
    built = ObservationIndex()
    built.extend(observations)
    return built


def load():
    return load_correlations_from_dir(RULES_DIR)


def baas(reachable=1, evidence_id=None):
    return Observation.ok(
        "baas_endpoints", TARGET,
        {"found": ["https://ref.supabase.co/rest/v1/"], "counts": {"reachable": reachable}},
        evidence_id=evidence_id,
    )


def cors(wildcard=True):
    return Observation.ok("http_cors", TARGET, {"wildcard": wildcard, "credentials": False})


def discover(paths=("/admin",)):
    return Observation.ok("explore_discover", TARGET, {"found_paths": list(paths)})


def headers(values=None):
    return Observation.ok("http_headers", TARGET, {"headers": dict(values or {})})


def assets(external=("cdn.example",), integrity=(False, True), evidence_id=None):
    page = {
        "assets": [{"integrity": value} for value in integrity],
        "counts": {"external": len(external)},
    }
    return Observation.ok(
        "explore_assets", TARGET,
        {"external_hosts": list(external), "pages": [page]},
        evidence_id=evidence_id,
    )


class TestFiles(unittest.TestCase):

    def test_directory_loads_three_rules(self):
        self.assertEqual(len(load()), 3)

    def test_every_rule_needs_two_collectors(self):
        for rule in load():
            self.assertGreaterEqual(len(set(rule.collectors)), 2)

    def test_ids_are_unique(self):
        ids = load().ids
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_carry_no_prefix_before_running(self):
        for rule in load():
            self.assertFalse(rule.id.startswith(CORRELATION_PREFIX))

    def test_every_rule_requires_proof_and_consent(self):
        for rule in load():
            self.assertEqual(set(rule.requires), {"proof", "consent"})


class TestBaasWildcardCors(unittest.TestCase):

    def test_match_is_low_confidence(self):
        result = run(load(), index(baas(), cors()), target=TARGET, satisfied=SATISFIED)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.low_confidence), 1)
        self.assertTrue(result.low_confidence[0].rule_id.startswith(CORRELATION_PREFIX))

    def test_no_wildcard_skips(self):
        result = run(load(), index(baas(), cors(wildcard=False)),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(dict(result.skipped)[BAAS], "no_match")

    def test_unreachable_baas_skips(self):
        result = run(load(), index(baas(reachable=0), cors()),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(dict(result.skipped)[BAAS], "no_match")

    def test_evidence_is_collected(self):
        result = run(load(), index(baas(evidence_id="ev_baas"), cors()),
                     target=TARGET, satisfied=SATISFIED)
        self.assertIn("ev_baas", result.low_confidence[0].evidence_ids)


class TestAdminWithoutAuthChallenge(unittest.TestCase):

    def test_match_is_low_confidence(self):
        result = run(load(), index(discover(), headers()),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(len(result.low_confidence), 1)
        self.assertEqual(result.low_confidence[0].rule_id, f"{CORRELATION_PREFIX}{ADMIN}")

    def test_auth_challenge_skips(self):
        result = run(load(), index(discover(), headers({"www-authenticate": "Basic"})),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(dict(result.skipped)[ADMIN], "no_match")

    def test_other_path_skips(self):
        result = run(load(), index(discover(("/login",)), headers()),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(dict(result.skipped)[ADMIN], "no_match")


class TestExternalAssetWithoutSriAndCsp(unittest.TestCase):

    def test_match_is_a_finding(self):
        result = run(load(), index(assets(), headers()), target=TARGET, satisfied=SATISFIED)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, f"{CORRELATION_PREFIX}{ASSETS}")

    def test_no_external_host_skips(self):
        result = run(load(), index(assets(external=()), headers()),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(dict(result.skipped)[ASSETS], "no_match")

    def test_full_integrity_skips(self):
        result = run(load(), index(assets(integrity=(True, True)), headers()),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(dict(result.skipped)[ASSETS], "no_match")

    def test_csp_present_skips(self):
        result = run(load(), index(assets(), headers({"content-security-policy": "default-src 'self'"})),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(dict(result.skipped)[ASSETS], "no_match")

    def test_evidence_is_collected(self):
        result = run(load(), index(assets(evidence_id="ev_asset"), headers()),
                     target=TARGET, satisfied=SATISFIED)
        self.assertEqual(result.findings[0].evidence_ids, ("ev_asset",))

    def test_unsatisfied_requires_skips(self):
        result = run(load(), index(assets(), headers()), target=TARGET, satisfied=[])
        self.assertEqual(dict(result.skipped)[ASSETS], "requires")

class TestNestedWalk(unittest.TestCase):

    def test_nested_lists_are_flattened(self):
        data = {"pages": [{"assets": [{"integrity": False}, {"integrity": True}]}]}
        self.assertEqual(_walk(data, ["pages", "assets", "integrity"]), [False, True])

    def test_missing_inner_key_stays_missing(self):
        data = {"pages": [{"assets": [{"integrity": False}]}]}
        self.assertIs(_walk(data, ["pages", "assets", "nope"]), MISSING)

    def test_empty_inner_list_is_missing(self):
        self.assertIs(
            _walk({"pages": [{"assets": []}]}, ["pages", "assets", "integrity"]),
            MISSING,
        )


if __name__ == "__main__":
    unittest.main()