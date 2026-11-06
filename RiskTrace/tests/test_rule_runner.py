import unittest

from engine.observations import Observation
from engine.rule_runner import (
    MISSING,
    ObservationIndex,
    by_severity,
    evaluate,
    finding_id,
    lookup,
    run,
)
from engine.rules import load_rules_from_text


def rule(**overrides):
    base = {
        "id": "HDR_HSTS_MISSING",
        "title": "HSTS 未設定",
        "severity": "LOW",
        "confidence": "high",
        "requires": ["consent", "proof"],
        "collectors": ["http_headers"],
        "when": {"obs": {"collector": "http_headers", "path": "headers",
                         "key": "strict-transport-security", "op": "absent"}},
        "message": "HSTS が返っていない",
        "why": "ダウングレードを検知できない",
        "fix": "HSTS を付与する",
        "verify": "再取得して確認する",
    }
    base.update(overrides)
    return base


def ruleset_of(*items):
    import yaml
    return load_rules_from_text(yaml.safe_dump(list(items), allow_unicode=True))


def obs(**overrides):
    base = {
        "collector": "http_headers",
        "subject": "https://example.test/",
        "data": {"headers": {"strict-transport-security": None}},
    }
    base.update(overrides)
    return Observation.ok(**base)


SATISFIED = frozenset({"consent", "proof"})


class TestLookup(unittest.TestCase):

    def test_nested_ref_is_resolved(self):
        found = list(lookup([obs()], "headers.strict-transport-security"))
        self.assertEqual(found[0][1], None)

    def test_missing_key_yields_nothing(self):
        self.assertEqual(list(lookup([obs()], "headers.nope")), [])

    def test_non_dict_branch_yields_nothing(self):
        self.assertEqual(list(lookup([obs(data={"a": "x"})], "a.b")), [])


class TestOperators(unittest.TestCase):

    def index(self, value):
        index = ObservationIndex()
        index.add(obs(data={"k": value}))
        return index

    def check(self, op, value, expected=None, compiled=None):
        from engine.rules import ObsPredicate

        predicate = ObsPredicate(collector="http_headers", path="k", key="", op=op,
                                 value=expected, compiled=compiled)
        return evaluate(predicate, self.index(value))[0]

    def test_eq(self):
        self.assertTrue(self.check("eq", "a", "a"))
        self.assertFalse(self.check("eq", "a", "b"))

    def test_ne(self):
        self.assertTrue(self.check("ne", "a", "b"))

    def test_present(self):
        self.assertTrue(self.check("present", "a"))
        self.assertFalse(self.check("present", None))

    def test_absent(self):
        self.assertTrue(self.check("absent", None))
        self.assertFalse(self.check("absent", "a"))

    def test_empty(self):
        self.assertTrue(self.check("empty", ""))
        self.assertTrue(self.check("empty", []))
        self.assertFalse(self.check("empty", "a"))

    def test_in_and_not_in(self):
        self.assertTrue(self.check("in", "a", ["a", "b"]))
        self.assertTrue(self.check("not_in", "c", ["a", "b"]))

    def test_contains_on_string(self):
        self.assertTrue(self.check("contains", "max-age=31536000", "max-age"))
        self.assertFalse(self.check("contains", "max-age", "includeSubDomains"))

    def test_contains_on_list(self):
        self.assertTrue(self.check("contains", ["a", "b"], "b"))

    def test_regex(self):
        import re
        self.assertTrue(self.check("regex", "SAMEORIGIN", None, re.compile("same", re.I)))

    def test_gt_lt(self):
        self.assertTrue(self.check("gt", 5, 3))
        self.assertTrue(self.check("lt", 3, 5))
        self.assertFalse(self.check("gt", "abc", 3))


class TestMissingCollector(unittest.TestCase):

    def test_absent_is_true_when_collector_did_not_run(self):
        from engine.rules import ObsPredicate

        predicate = ObsPredicate(collector="nope", path="k", key="", op="absent")
        self.assertTrue(evaluate(predicate, ObservationIndex())[0])

    def test_present_is_false_when_collector_did_not_run(self):
        from engine.rules import ObsPredicate

        predicate = ObsPredicate(collector="nope", path="k", key="", op="present")
        self.assertFalse(evaluate(predicate, ObservationIndex())[0])


class TestRun(unittest.TestCase):

    def test_matching_rule_produces_finding(self):
        normal, low = run(ruleset_of(rule()), [obs()], satisfied=SATISFIED)
        self.assertEqual(len(normal), 1)
        self.assertEqual(normal[0].rule_id, "HDR_HSTS_MISSING")

    def test_non_matching_rule_produces_nothing(self):
        normal, _ = run(ruleset_of(rule()), [obs(data={"headers": {"strict-transport-security": "max-age=1"}})],
                        satisfied=SATISFIED)
        self.assertEqual(normal, [])

    def test_finding_carries_rule_content(self):
        normal, _ = run(ruleset_of(rule()), [obs()], satisfied=SATISFIED)
        finding = normal[0]
        self.assertEqual(finding.severity, "LOW")
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(finding.subject, "https://example.test/")
        self.assertEqual(finding.fix, "HSTS を付与する")

    def test_evidence_ids_are_collected(self):
        observation = obs().with_evidence("ev_1")
        normal, _ = run(ruleset_of(rule()), [observation], satisfied=SATISFIED)
        self.assertEqual(normal[0].evidence_ids, ("ev_1",))

    def test_low_confidence_is_separated(self):
        normal, low = run(ruleset_of(rule(confidence="low")), [obs()], satisfied=SATISFIED)
        self.assertEqual(normal, [])
        self.assertEqual(len(low), 1)

    def test_requires_gate_blocks_rule(self):
        normal, _ = run(ruleset_of(rule()), [obs()], satisfied=frozenset({"proof"}))
        self.assertEqual(normal, [])

    def test_duplicate_findings_are_collapsed(self):
        normal, _ = run(ruleset_of(rule()), [obs(), obs()], satisfied=SATISFIED)
        self.assertEqual(len(normal), 1)

    def test_skipped_observation_is_ignored(self):
        skipped = Observation.skipped("http_headers", "https://example.test/", "予算切れ")
        normal, _ = run(ruleset_of(rule()), [skipped], satisfied=SATISFIED)
        self.assertEqual(normal, [])

    def test_finding_id_is_stable(self):
        self.assertEqual(finding_id("A", "x"), finding_id("A", "x"))
        self.assertNotEqual(finding_id("A", "x"), finding_id("B", "x"))


class TestAllAnyNot(unittest.TestCase):

    def test_all_requires_every_child(self):
        item = rule(when={"all": [
            {"obs": {"collector": "http_headers", "path": "headers", "key": "a", "op": "present"}},
            {"obs": {"collector": "http_headers", "path": "headers", "key": "b", "op": "present"}},
        ]})
        normal, _ = run(ruleset_of(item), [obs(data={"headers": {"a": "1"}})], satisfied=SATISFIED)
        self.assertEqual(normal, [])

    def test_any_needs_one_child(self):
        item = rule(when={"any": [
            {"obs": {"collector": "http_headers", "path": "headers", "key": "a", "op": "present"}},
            {"obs": {"collector": "http_headers", "path": "headers", "key": "b", "op": "present"}},
        ]})
        normal, _ = run(ruleset_of(item), [obs(data={"headers": {"a": "1"}})], satisfied=SATISFIED)
        self.assertEqual(len(normal), 1)

    def test_not_inverts(self):
        item = rule(when={"not": {"obs": {"collector": "http_headers", "path": "headers",
                                          "key": "a", "op": "present"}}})
        normal, _ = run(ruleset_of(item), [obs(data={"headers": {}})], satisfied=SATISFIED)
        self.assertEqual(len(normal), 1)


class TestOrdering(unittest.TestCase):

    def test_by_severity_sorts_descending(self):
        normal, _ = run(
            ruleset_of(rule(id="A", severity="LOW"),
                       rule(id="B", severity="CRITICAL")),
            [obs()], satisfied=SATISFIED,
        )
        self.assertEqual([f.severity for f in by_severity(normal)], ["CRITICAL", "LOW"])


if __name__ == "__main__":
    unittest.main()