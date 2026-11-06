import unittest

from analyzer.scoring_v2 import score
from engine.rule_runner import Finding

URL = "https://example.test/"


def finding(rule_id="r", severity="MEDIUM", confidence="high", tags=(), evidence=()):
    return Finding(
        id=f"fnd_{rule_id}",
        rule_id=rule_id,
        title="t",
        severity=severity,
        confidence=confidence,
        subject=URL,
        message="m",
        why="w",
        fix="f",
        verify="v",
        evidence_ids=tuple(evidence),
        tags=tuple(tags),
    )


class TestEmpty(unittest.TestCase):

    def test_no_findings_scores_zero(self):
        result = score([])
        self.assertEqual(result.overall, 0)
        self.assertEqual(result.level, "LOW")

    def test_coverage_is_none_without_a_plan(self):
        self.assertIsNone(score([]).coverage)


class TestAxes(unittest.TestCase):

    def test_severity_raises_impact(self):
        low = score([finding(severity="LOW")])
        high = score([finding(severity="HIGH")])
        self.assertGreater(high.axes["impact"], low.axes["impact"])

    def test_exposure_tag_raises_reachability(self):
        plain = score([finding()])
        exposed = score([finding(tags=("exposure",))])
        self.assertGreater(exposed.axes["reachability"], plain.axes["reachability"])

    def test_axes_are_capped_at_100(self):
        many = [finding(rule_id=f"r{i}", severity="CRITICAL") for i in range(200)]
        result = score(many)
        for value in result.axes.values():
            self.assertLessEqual(value, 100)

    def test_overall_never_exceeds_100(self):
        many = [finding(rule_id=f"r{i}", severity="CRITICAL", tags=("exposure",)) for i in range(200)]
        self.assertLessEqual(score(many).overall, 100)


class TestConfidence(unittest.TestCase):

    def test_medium_confidence_scores_lower(self):
        self.assertGreater(
            score([finding(confidence="high")]).overall,
            score([finding(confidence="medium")]).overall,
        )

    def test_low_confidence_is_excluded_by_default(self):
        result = score([finding(confidence="low")])
        self.assertEqual(result.overall, 0)
        self.assertEqual(result.excluded_low_confidence, 1)

    def test_low_confidence_can_be_included(self):
        result = score([finding(confidence="low")], include_low_confidence=True)
        self.assertGreater(result.overall, 0)
        self.assertEqual(result.excluded_low_confidence, 0)


class TestDedupe(unittest.TestCase):

    def test_same_rule_counts_once(self):
        result = score([finding(rule_id="same"), finding(rule_id="same")])
        self.assertEqual(sum(result.counts.values()), 1)

    def test_highest_severity_is_kept(self):
        result = score([finding(rule_id="same", severity="LOW"),
                        finding(rule_id="same", severity="HIGH")])
        self.assertEqual(result.counts["HIGH"], 1)
        self.assertEqual(result.counts["LOW"], 0)

    def test_evidence_is_merged(self):
        result = score([finding(rule_id="same", evidence=("ev_1",)),
                        finding(rule_id="same", severity="HIGH", evidence=("ev_2",))])
        self.assertEqual(set(result.evidence_ids), {"ev_1", "ev_2"})

    def test_different_rules_count_separately(self):
        result = score([finding(rule_id="a"), finding(rule_id="b")])
        self.assertEqual(sum(result.counts.values()), 2)


class TestCoverage(unittest.TestCase):

    def test_low_coverage_lowers_the_score(self):
        full = score([finding()], executed=10, planned=10)
        partial = score([finding()], executed=1, planned=10)
        self.assertGreater(full.overall, partial.overall)

    def test_coverage_is_reported(self):
        self.assertEqual(score([], executed=2, planned=4).coverage, 0.5)

    def test_zero_planned_leaves_coverage_none(self):
        self.assertIsNone(score([finding()], executed=0, planned=0).coverage)

    def test_full_coverage_does_not_raise_above_axes(self):
        result = score([finding()], executed=4, planned=4)
        self.assertLessEqual(result.overall, max(result.axes.values()))


class TestLevels(unittest.TestCase):

    def test_thresholds_follow_the_existing_scale(self):
        many = [finding(rule_id=f"r{i}", severity="CRITICAL", tags=("exposure",)) for i in range(50)]
        result = score(many, executed=10, planned=10)
        self.assertIn(result.level, ("CRITICAL", "HIGH"))

    def test_result_serialises(self):
        payload = score([finding()]).to_dict()
        self.assertIn("axes", payload)
        self.assertIn("coverage", payload)


if __name__ == "__main__":
    unittest.main()