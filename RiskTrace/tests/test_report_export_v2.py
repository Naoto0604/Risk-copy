import csv
import io
import json
import unittest

from engine.scoring_v2 import score
from engine.rule_runner import Finding
from report import export, model

URL = "https://example.test/"


def finding(rule_id="r", severity="MEDIUM", evidence=()):
    return Finding(
        id="fnd_1",
        rule_id=rule_id,
        title="title",
        severity=severity,
        confidence="high",
        subject=URL,
        message="m",
        why="w",
        fix="fix",
        verify="v",
        evidence_ids=tuple(evidence),
    )


def build(**kwargs):
    kwargs.setdefault("score_result", score([]))
    return model.build(URL, **kwargs)


class TestJson(unittest.TestCase):

    def test_payload_has_schema_version(self):
        self.assertEqual(export.build_payload(build())["schema_version"], export.SCHEMA_VERSION)

    def test_findings_are_present(self):
        payload = export.build_payload(build(findings=[finding(evidence=("ev_1",))]))
        self.assertEqual(payload["groups"][0]["evidence_ids"], ["ev_1"])

    def test_japanese_is_not_escaped(self):
        report = build(skipped=[("dns", "not_consented")])
        self.assertIn("同意".encode("utf-8"), export.build_json_bytes(report))

    def test_json_is_loadable(self):
        payload = json.loads(export.build_json_bytes(build(findings=[finding()])))
        self.assertEqual(payload["target"], URL)

    def test_previous_is_included(self):
        payload = export.build_payload(build(previous={"overall": 10}))
        self.assertEqual(payload["previous"]["overall"], 10)


class TestCsv(unittest.TestCase):

    def parse(self, report):
        text = export.build_csv_bytes(report).decode("utf-8")
        return list(csv.DictReader(io.StringIO(text)))

    def test_header_is_stable(self):
        rows = self.parse(build())
        self.assertEqual(tuple(rows[0].keys()), export.CSV_COLUMNS) if rows else None
        header = export.build_csv_bytes(build()).decode("utf-8").splitlines()[0]
        self.assertEqual(tuple(header.split(",")), export.CSV_COLUMNS)

    def test_findings_are_exported(self):
        rows = self.parse(build(findings=[finding(evidence=("ev_1",))]))
        self.assertEqual(rows[0]["section"], "finding")
        self.assertIn("ev_1", rows[0]["evidence_ids"])

    def test_low_confidence_has_its_own_section(self):
        report = build(low_confidence=[Finding(
            id="f", rule_id="low", title="t", severity="LOW", confidence="low",
            subject=URL, message="m", why="w", fix="f", verify="v",
        )])
        self.assertEqual(self.parse(report)[0]["section"], "low_confidence")

    def test_needs_review_is_exported(self):
        rows = self.parse(build(skipped=[("dns", "not_consented")]))
        self.assertEqual(rows[0]["section"], "needs_review")

    def test_evidence_is_exported(self):
        class Observation:
            collector = "http_headers"
            subject = URL
            status = "ok"
            evidence_id = "ev_1"
            is_error = False
            has_evidence = True

        rows = self.parse(build(observations=[Observation()]))
        self.assertEqual(rows[0]["section"], "evidence")
        self.assertEqual(rows[0]["evidence_ids"], "ev_1")


class TestFormulaInjection(unittest.TestCase):

    def test_equals_is_escaped(self):
        self.assertEqual(export._cell("=1+1"), "'=1+1")

    def test_plus_is_escaped(self):
        self.assertEqual(export._cell("+1"), "'+1")

    def test_minus_is_escaped(self):
        self.assertEqual(export._cell("-1"), "'-1")

    def test_at_is_escaped(self):
        self.assertEqual(export._cell("@x"), "'@x")

    def test_plain_text_is_untouched(self):
        self.assertEqual(export._cell("abc"), "abc")

    def test_leading_space_still_escapes(self):
        self.assertEqual(export._cell(" =1"), "' =1")

    def test_none_becomes_empty(self):
        self.assertEqual(export._cell(None), "")

    def test_list_is_joined(self):
        self.assertEqual(export._cell(("a", "b")), "a b")

    def test_injected_title_is_escaped_in_csv(self):
        report = build(findings=[Finding(
            id="f", rule_id="r", title="=SUM(A1)", severity="LOW", confidence="high",
            subject=URL, message="m", why="w", fix="f", verify="v",
        )])
        text = export.build_csv_bytes(report).decode("utf-8")
        self.assertIn("'=SUM(A1)", text)


if __name__ == "__main__":
    unittest.main()