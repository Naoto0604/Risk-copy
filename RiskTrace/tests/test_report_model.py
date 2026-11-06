import unittest

from analyzer.scoring_v2 import score
from engine.rule_runner import Finding
from report import model

URL = "https://example.test/"


def finding(rule_id="r", severity="MEDIUM", confidence="high", subject=URL, evidence=()):
    return Finding(
        id=f"fnd_{rule_id}_{subject}",
        rule_id=rule_id,
        title=f"title {rule_id}",
        severity=severity,
        confidence=confidence,
        subject=subject,
        message="m",
        why="w",
        fix="fix",
        verify="v",
        evidence_ids=tuple(evidence),
    )


def build(**kwargs):
    kwargs.setdefault("score_result", score([]))
    return model.build(URL, **kwargs)


class TestGroups(unittest.TestCase):

    def test_same_rule_is_grouped(self):
        report = build(findings=[finding(rule_id="a"), finding(rule_id="a", subject=URL + "x")])
        self.assertEqual(len(report.groups), 1)
        self.assertEqual(report.groups[0].count, 2)

    def test_subjects_are_kept_per_group(self):
        report = build(findings=[finding(rule_id="a"), finding(rule_id="a", subject=URL + "x")])
        self.assertEqual(len(report.groups[0].subjects), 2)

    def test_groups_are_sorted_by_severity(self):
        report = build(findings=[finding(rule_id="low", severity="LOW"),
                                 finding(rule_id="high", severity="HIGH")])
        self.assertEqual(report.groups[0].rule_id, "high")

    def test_correlations_are_merged_into_groups(self):
        report = build(correlations=[finding(rule_id="corr:a")])
        self.assertEqual(report.groups[0].rule_id, "corr:a")


class TestActions(unittest.TestCase):

    def test_actions_are_capped(self):
        items = [finding(rule_id=f"r{i}") for i in range(10)]
        self.assertEqual(len(build(findings=items).actions), model.MAX_ACTIONS)

    def test_action_takes_the_most_severe(self):
        items = [finding(rule_id="low", severity="LOW"), finding(rule_id="crit", severity="CRITICAL")]
        self.assertEqual(build(findings=items).actions[0].rule_id, "crit")

    def test_action_has_a_reason(self):
        self.assertTrue(build(findings=[finding()]).actions[0].reason)


class TestLowConfidence(unittest.TestCase):

    def test_low_confidence_is_separated(self):
        report = build(findings=[finding(rule_id="normal")],
                       low_confidence=[finding(rule_id="low", confidence="low")])
        self.assertEqual([g.rule_id for g in report.groups], ["normal"])
        self.assertEqual([g.rule_id for g in report.low_confidence], ["low"])

    def test_low_correlation_is_separated(self):
        report = build(low_correlations=[finding(rule_id="corr:low", confidence="low")])
        self.assertEqual(report.groups, ())
        self.assertEqual(len(report.low_confidence), 1)


class TestReview(unittest.TestCase):

    def test_skipped_collector_becomes_review_item(self):
        report = build(skipped=[("dns", "not_consented")])
        self.assertEqual(report.needs_review[0].kind, "collector")
        self.assertIn("同意", report.needs_review[0].detail)

    def test_missing_need_reason_is_readable(self):
        report = build(skipped=[("explore_assets", "needs:explore_crawl")])
        self.assertIn("explore_crawl", report.needs_review[0].detail)

    def test_low_coverage_becomes_review_item(self):
        report = build(score_result=score([], executed=1, planned=10))
        self.assertIn("coverage", [item.kind for item in report.needs_review])

    def test_full_coverage_adds_no_coverage_item(self):
        report = build(score_result=score([], executed=4, planned=4))
        self.assertEqual([item.kind for item in report.needs_review], [])

    def test_review_count_is_exposed(self):
        self.assertEqual(build(skipped=[("dns", "empty")]).review_count, 1)


class TestStatusNote(unittest.TestCase):

    def test_note_mentions_incomplete_runs(self):
        report = build(skipped=[("dns", "empty")])
        self.assertIn("0 件は安全を意味しません", report.status_note)

    def test_note_says_complete_when_nothing_skipped(self):
        report = build(score_result=score([], executed=2, planned=2))
        self.assertIn("すべて実行", report.status_note)


class TestEvidence(unittest.TestCase):

    def test_evidence_ids_are_listed(self):
        class Observation:
            collector = "http_headers"
            subject = URL
            status = "ok"
            evidence_id = "ev_1"
            is_error = False
            has_evidence = True

        report = build(observations=[Observation()])
        self.assertEqual(report.evidence[0].evidence_id, "ev_1")

    def test_error_observation_becomes_review_item(self):
        class Observation:
            collector = "dns"
            subject = URL
            status = "error"
            evidence_id = None
            is_error = True
            has_evidence = False
            note = "タイムアウト"

        report = build(observations=[Observation()])
        self.assertEqual(report.needs_review[0].kind, "observation")
        self.assertEqual(report.evidence, ())


class TestModel(unittest.TestCase):

    def test_empty_target_raises(self):
        with self.assertRaises(model.ReportError):
            model.build(" ", score_result=score([]))

    def test_to_dict_is_serialisable(self):
        payload = build(findings=[finding()]).to_dict()
        self.assertEqual(payload["target"], URL)
        self.assertIn("needs_review", payload)

    def test_previous_is_passed_through(self):
        report = build(previous={"overall": 40, "level": "MEDIUM"})
        self.assertEqual(report.previous["overall"], 40)


if __name__ == "__main__":
    unittest.main()