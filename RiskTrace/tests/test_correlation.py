import unittest

import yaml

from engine.correlation import (
    CORRELATION_PREFIX,
    load_correlations_from_text,
    run,
)
from engine.observations import Observation
from engine.rule_runner import ObservationIndex
from engine.rules import RuleLoadError

TARGET = "https://example.test/"


def correlation(**overrides):
    rule = {
        "id": "wildcard_with_credentials",
        "title": "ワイルドカード許可と資格情報許可が併用されています",
        "severity": "MEDIUM",
        "confidence": "medium",
        "requires": ["consent"],
        "collectors": ["http_cors", "http_headers"],
        "when": {
            "all": [
                {"obs": {"collector": "http_cors", "key": "wildcard", "op": "eq", "value": True}},
                {"obs": {"collector": "http_cors", "key": "credentials", "op": "eq", "value": True}},
            ]
        },
        "message": "任意の送信元が資格情報付きで読めます",
        "why": "理由",
        "fix": "修正",
        "verify": "確認",
    }
    rule.update(overrides)
    return rule


def load(**overrides):
    return load_correlations_from_text(yaml.safe_dump([correlation(**overrides)]), "test.yaml")


def cors(wildcard=True, credentials=True, evidence_id="ev_1"):
    return Observation.ok(
        "http_cors", TARGET,
        {"wildcard": wildcard, "credentials": credentials},
        evidence_id=evidence_id,
    )


def headers(**data):
    return Observation.ok("http_headers", TARGET, data)


def index(*observations):
    built = ObservationIndex()
    built.extend(observations)
    return built


class TestLoad(unittest.TestCase):

    def test_valid_rule_loads(self):
        self.assertEqual(len(load()), 1)

    def test_single_collector_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load(collectors=["http_cors"])

    def test_reference_outside_collectors_is_rejected(self):
        when = {"obs": {"collector": "http_headers", "key": "headers", "op": "present"}}
        with self.assertRaises(RuleLoadError):
            load(collectors=["http_cors", "dns"], when=when)

    def test_missing_confidence_is_rejected(self):
        rule = correlation()
        del rule["confidence"]
        with self.assertRaises(RuleLoadError):
            load_correlations_from_text(yaml.safe_dump([rule]), "test.yaml")

    def test_unknown_key_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load(unknown_key=1)


class TestRun(unittest.TestCase):

    def test_matching_correlation_produces_a_finding(self):
        result = run(load(), index(cors(), headers()), target=TARGET, satisfied=["consent"])
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.findings[0].rule_id.startswith(CORRELATION_PREFIX))

    def test_subject_is_the_target(self):
        result = run(load(), index(cors(), headers()), target=TARGET, satisfied=["consent"])
        self.assertEqual(result.findings[0].subject, TARGET)

    def test_evidence_is_collected(self):
        result = run(load(), index(cors(evidence_id="ev_9"), headers()),
                     target=TARGET, satisfied=["consent"])
        self.assertEqual(result.findings[0].evidence_ids, ("ev_9",))

    def test_observed_values_are_kept(self):
        result = run(load(), index(cors(), headers()), target=TARGET, satisfied=["consent"])
        self.assertTrue(result.findings[0].observed)

    def test_missing_collector_skips_the_rule(self):
        result = run(load(), index(cors()), target=TARGET, satisfied=["consent"])
        self.assertEqual(result.findings, ())
        self.assertEqual(
            dict(result.skipped)["wildcard_with_credentials"],
            "missing_collector:http_headers",
        )

    def test_no_match_skips_the_rule(self):
        result = run(load(), index(cors(wildcard=False), headers()),
                     target=TARGET, satisfied=["consent"])
        self.assertEqual(result.findings, ())
        self.assertEqual(dict(result.skipped)["wildcard_with_credentials"], "no_match")

    def test_unsatisfied_requires_skips_the_rule(self):
        result = run(load(), index(cors(), headers()), target=TARGET, satisfied=[])
        self.assertEqual(result.findings, ())
        self.assertEqual(dict(result.skipped)["wildcard_with_credentials"], "requires")

    def test_low_confidence_is_separated(self):
        result = run(load(confidence="low"), index(cors(), headers()),
                     target=TARGET, satisfied=["consent"])
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.low_confidence), 1)

    def test_skipped_observations_are_ignored(self):
        skipped = Observation.skipped("http_headers", TARGET, "対象外")
        result = run(load(), index(cors(), skipped), target=TARGET, satisfied=["consent"])
        self.assertEqual(result.findings, ())

    def test_empty_index_skips_everything(self):
        result = run(load(), index(), target=TARGET, satisfied=["consent"])
        self.assertEqual(len(result.skipped), 1)

    def test_empty_target_raises(self):
        with self.assertRaises(ValueError):
            run(load(), index(), target=" ")

    def test_finding_id_is_stable(self):
        first = run(load(), index(cors(), headers()), target=TARGET, satisfied=["consent"])
        second = run(load(), index(cors(), headers()), target=TARGET, satisfied=["consent"])
        self.assertEqual(first.findings[0].id, second.findings[0].id)


if __name__ == "__main__":
    unittest.main()