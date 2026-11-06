import tempfile
import unittest
from pathlib import Path

from engine.rules import (
    AllPredicate,
    AnyPredicate,
    NotPredicate,
    ObsPredicate,
    RuleLoadError,
    RuleSet,
    build_ref,
    load_rules_from_dir,
    load_rules_from_text,
)


def valid_rule(**overrides):
    rule = {
        "id": "HEADER_HSTS_MISSING",
        "title": "HSTS が設定されていない",
        "severity": "LOW",
        "confidence": "high",
        "requires": ["consent", "proof"],
        "collectors": ["http_headers"],
        "when": {"obs": {"collector": "http_headers", "path": "headers",
                         "key": "strict-transport-security", "op": "absent"}},
        "message": "HSTS ヘッダーが返っていない",
        "why": "HTTP へのダウングレードを検知できない",
        "fix": "Strict-Transport-Security を付与する",
        "verify": "応答ヘッダーを再取得して確認する",
    }
    rule.update(overrides)
    return rule


def yaml_of(*rules):
    import yaml
    return yaml.safe_dump(list(rules), allow_unicode=True)


def load_one(**overrides):
    return load_rules_from_text(yaml_of(valid_rule(**overrides)))


class TestBuildRef(unittest.TestCase):

    def test_both_parts_are_joined_with_a_dot(self):
        self.assertEqual(build_ref("headers", "x-frame-options"), "headers.x-frame-options")

    def test_path_only_is_used_as_is(self):
        self.assertEqual(build_ref("headers", None), "headers")
        self.assertEqual(build_ref("headers", ""), "headers")

    def test_key_only_is_used_as_is(self):
        self.assertEqual(build_ref(None, "x-frame-options"), "x-frame-options")
        self.assertEqual(build_ref("", "x-frame-options"), "x-frame-options")

    def test_both_empty_is_an_error(self):
        for path, key in ((None, None), ("", ""), ("  ", "  "), (".", ".")):
            with self.assertRaises(ValueError, msg=f"{path!r}/{key!r}"):
                build_ref(path, key)

    def test_edges_are_stripped(self):
        self.assertEqual(build_ref(" headers ", " key "), "headers.key")
        self.assertEqual(build_ref(".headers.", ".key."), "headers.key")

    def test_obs_ref_uses_the_same_rule(self):
        obs = ObsPredicate(collector="c", path="a", key="b", op="eq", value=1)
        self.assertEqual(obs.ref, "a.b")


class TestRequiredKeys(unittest.TestCase):

    def test_each_required_key_is_enforced(self):
        for key in (
            "id", "title", "severity", "confidence", "requires",
            "collectors", "when", "message", "why", "fix", "verify",
        ):
            with self.subTest(key=key):
                rule = valid_rule()
                del rule[key]
                with self.assertRaises(RuleLoadError) as ctx:
                    load_rules_from_text(yaml_of(rule))
                self.assertIn(key, str(ctx.exception))

    def test_missing_confidence_is_reported_explicitly(self):
        rule = valid_rule()
        del rule["confidence"]
        with self.assertRaises(RuleLoadError) as ctx:
            load_rules_from_text(yaml_of(rule))
        self.assertIn("confidence", str(ctx.exception))

    def test_empty_confidence_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(confidence="")

    def test_unknown_confidence_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(confidence="certain")


class TestSeverity(unittest.TestCase):

    def test_allowed_values_are_accepted(self):
        for severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            with self.subTest(severity=severity):
                self.assertEqual(len(load_one(severity=severity)), 1)

    def test_lowercase_is_normalized(self):
        rule = next(iter(load_one(severity="high")))
        self.assertEqual(rule.severity, "HIGH")

    def test_unknown_severity_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(severity="SEVERE")


class TestUnknownKeys(unittest.TestCase):

    def test_unknown_top_level_key_is_rejected(self):
        with self.assertRaises(RuleLoadError) as ctx:
            load_one(unknown="x")
        self.assertIn("未知のキー", str(ctx.exception))

    def test_unknown_predicate_key_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"obs": {"collector": "c", "path": "p", "op": "present"},
                           "extra": True})

    def test_unknown_obs_key_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"obs": {"collector": "c", "path": "p", "op": "present",
                                   "value_type": "str"}})


class TestPredicateStructure(unittest.TestCase):

    def test_two_kinds_in_one_predicate_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"all": [{"obs": {"collector": "c", "path": "p", "op": "present"}}],
                           "not": {"obs": {"collector": "c", "path": "p", "op": "present"}}})

    def test_empty_kind_list_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"all": []})

    def test_not_requires_a_mapping(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"not": []})

    def test_obs_requires_a_collector(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"obs": {"path": "p", "op": "present"}})

    def test_nesting_is_preserved(self):
        rule = next(iter(load_one(when={"all": [
            {"obs": {"collector": "c", "path": "p", "op": "present"}},
            {"any": [{"obs": {"collector": "c", "path": "q", "op": "empty"}}]},
            {"not": {"obs": {"collector": "c", "path": "r", "op": "absent"}}},
        ]})))
        self.assertIsInstance(rule.when, AllPredicate)
        self.assertIsInstance(rule.when.children[1], AnyPredicate)
        self.assertIsInstance(rule.when.children[2], NotPredicate)


class TestOperators(unittest.TestCase):

    def test_unknown_op_is_rejected(self):
        with self.assertRaises(RuleLoadError) as ctx:
            load_one(when={"obs": {"collector": "c", "path": "p", "op": "matches"}})
        self.assertIn("未知の op", str(ctx.exception))

    def test_missing_op_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"obs": {"collector": "c", "path": "p"}})

    def test_value_is_required_where_needed(self):
        for op in ("eq", "ne", "in", "not_in", "contains", "regex", "gt", "lt"):
            with self.subTest(op=op):
                with self.assertRaises(RuleLoadError) as ctx:
                    load_one(when={"obs": {"collector": "c", "path": "p", "op": op}})
                self.assertIn("value", str(ctx.exception))

    def test_value_is_not_required_for_presence_ops(self):
        for op in ("present", "absent", "empty"):
            with self.subTest(op=op):
                rule = next(iter(load_one(when={"obs": {"collector": "c", "path": "p", "op": op}})))
                self.assertEqual(rule.when.op, op)

    def test_list_ops_require_a_list(self):
        for op in ("in", "not_in"):
            with self.subTest(op=op):
                with self.assertRaises(RuleLoadError):
                    load_one(when={"obs": {"collector": "c", "path": "p", "op": op, "value": "x"}})

    def test_numeric_ops_require_a_number(self):
        for op in ("gt", "lt"):
            with self.subTest(op=op):
                with self.assertRaises(RuleLoadError):
                    load_one(when={"obs": {"collector": "c", "path": "p", "op": op, "value": "3"}})

    def test_numeric_ops_reject_bool(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"obs": {"collector": "c", "path": "p", "op": "gt", "value": True}})


class TestRegex(unittest.TestCase):

    def test_valid_regex_is_compiled_at_load(self):
        rule = next(iter(load_one(when={"obs": {"collector": "c", "path": "p",
                                               "op": "regex", "value": "^abc$"}})))
        self.assertIsNotNone(rule.when.compiled)
        self.assertTrue(rule.when.compiled.match("abc"))

    def test_broken_regex_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"obs": {"collector": "c", "path": "p", "op": "regex", "value": "([a-z"}})

    def test_overlong_regex_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(when={"obs": {"collector": "c", "path": "p", "op": "regex",
                                   "value": "a" * 600}})

    def test_nested_quantifier_is_rejected(self):
        for pattern in ("(.*)*", "(.+)+", "(a+)*"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(RuleLoadError):
                    load_one(when={"obs": {"collector": "c", "path": "p",
                                           "op": "regex", "value": pattern}})

    def test_realistic_domain_pattern_is_accepted(self):
        load_one(when={"obs": {"collector": "c", "path": "p",
                               "op": "regex", "value": r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$"}})


class TestRequiresAndCollectors(unittest.TestCase):

    def test_unknown_requirement_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(requires=["consent", "ownership"])

    def test_empty_requires_is_allowed(self):
        rule = next(iter(load_one(requires=[])))
        self.assertEqual(rule.requires, ())

    def test_requires_must_be_a_list(self):
        with self.assertRaises(RuleLoadError):
            load_one(requires="consent")

    def test_empty_collectors_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(collectors=[])

    def test_collectors_must_be_a_list(self):
        with self.assertRaises(RuleLoadError):
            load_one(collectors="http_headers")


class TestDuplicateIds(unittest.TestCase):

    def test_duplicate_id_in_one_file_is_rejected(self):
        with self.assertRaises(RuleLoadError) as ctx:
            load_rules_from_text(yaml_of(valid_rule(), valid_rule()))
        self.assertIn("重複", str(ctx.exception))

    def test_duplicate_id_across_files_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.yaml", "b.yaml"):
                Path(tmp, name).write_text(yaml_of(valid_rule()), encoding="utf-8")
            with self.assertRaises(RuleLoadError):
                load_rules_from_dir(tmp)

    def test_distinct_ids_are_all_kept(self):
        ruleset = load_rules_from_text(yaml_of(
            valid_rule(id="A_ONE"), valid_rule(id="A_TWO"),
        ))
        self.assertEqual(len(ruleset), 2)


class TestIdFormat(unittest.TestCase):

    def test_id_with_spaces_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_one(id="HSTS missing")

    def test_dotted_and_dashed_ids_are_accepted(self):
        load_one(id="header.hsts-missing.v2")


class TestDocumentShape(unittest.TestCase):

    def test_empty_document_is_allowed(self):
        self.assertEqual(len(load_rules_from_text("")), 0)

    def test_top_level_mapping_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_rules_from_text("id: X\n")

    def test_broken_yaml_is_rejected(self):
        with self.assertRaises(RuleLoadError):
            load_rules_from_text("id: [\n")

    def test_zero_rules_directory_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(len(load_rules_from_dir(tmp)), 0)

    def test_missing_directory_is_allowed(self):
        self.assertEqual(len(load_rules_from_dir(Path(tempfile.gettempdir()) / "no-such-rules-xyz")), 0)


class TestRuleSet(unittest.TestCase):

    def test_valid_rule_round_trips(self):
        rule = next(iter(load_one()))
        self.assertEqual(rule.id, "HEADER_HSTS_MISSING")
        self.assertEqual(rule.severity, "LOW")
        self.assertEqual(rule.confidence, "high")
        self.assertEqual(rule.requires, ("consent", "proof"))
        self.assertEqual(rule.collectors, ("http_headers",))
        self.assertEqual(rule.when.ref, "headers.strict-transport-security")
        self.assertEqual(rule.evidence, ())
        self.assertEqual(rule.tags, ())

    def test_by_collector_and_by_id(self):
        ruleset = load_rules_from_text(yaml_of(
            valid_rule(id="A_ONE", collectors=["http_headers"]),
            valid_rule(id="B_TWO", collectors=["cookies"]),
        ))
        self.assertEqual([r.id for r in ruleset.by_collector("cookies")], ["B_TWO"])
        self.assertEqual(ruleset.by_id("A_ONE").id, "A_ONE")
        self.assertIsNone(ruleset.by_id("NOPE"))
        self.assertEqual(ruleset.collectors, frozenset({"http_headers", "cookies"}))

    def test_empty_ruleset_behaves(self):
        ruleset = RuleSet()
        self.assertEqual(len(ruleset), 0)
        self.assertEqual(list(ruleset), [])

    def test_errors_are_collected_not_short_circuited(self):
        with self.assertRaises(RuleLoadError) as ctx:
            load_one(severity="BAD", confidence="BAD")
        self.assertGreaterEqual(len(ctx.exception.errors), 2)


if __name__ == "__main__":
    unittest.main()