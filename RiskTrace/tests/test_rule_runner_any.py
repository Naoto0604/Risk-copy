import unittest

from engine.observations import Observation
from engine.rule_runner import run
from engine.rules import load_rules_from_text

URL = "https://example.test/"


def ruleset():
    text = """
- id: probe.any
  title: any の確認
  severity: LOW
  confidence: high
  requires:
    - proof
  collectors:
    - probe
  when:
    any:
      - obs:
          collector: probe
          key: a
          op: eq
          value: true
      - obs:
          collector: probe
          key: b
          op: eq
          value: true
  message: メッセージ
  why: 理由
  fix: 修正
  verify: 確認
"""
    return load_rules_from_text(text, "probe.yaml")


def probe(a=False, b=False):
    return Observation.ok("probe", URL, {"a": a, "b": b})


class TestAny(unittest.TestCase):

    def test_first_branch_matches(self):
        normal, _low = run(ruleset(), [probe(a=True)], satisfied=frozenset({"proof"}))
        self.assertEqual(len(normal), 1)

    def test_second_branch_matches(self):
        normal, _low = run(ruleset(), [probe(b=True)], satisfied=frozenset({"proof"}))
        self.assertEqual(len(normal), 1)

    def test_both_branches_match(self):
        normal, _low = run(ruleset(), [probe(a=True, b=True)], satisfied=frozenset({"proof"}))
        self.assertEqual(len(normal), 1)

    def test_no_branch_matches(self):
        normal, _low = run(ruleset(), [probe()], satisfied=frozenset({"proof"}))
        self.assertEqual(normal, [])

    def test_any_does_not_duplicate(self):
        normal, _low = run(ruleset(), [probe(a=True, b=True)], satisfied=frozenset({"proof"}))
        self.assertEqual(len({finding.rule_id for finding in normal}), 1)


if __name__ == "__main__":
    unittest.main()