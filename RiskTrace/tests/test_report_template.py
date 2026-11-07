import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from engine.scoring_v2 import score
from engine.rule_runner import Finding
from report import model

URL = "https://example.test/"

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def environment():
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )


def finding(rule_id="r", title="title", severity="MEDIUM", confidence="high", evidence=()):
    return Finding(
        id="fnd_1",
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        subject=URL,
        message="m",
        why="w",
        fix="fix",
        verify="v",
        evidence_ids=tuple(evidence),
    )


def render(**kwargs):
    kwargs.setdefault("score_result", score([]))
    report = model.build(URL, **kwargs)
    return environment().get_template("report_v2.html").render(report=report)


class TestRender(unittest.TestCase):

    def test_target_is_shown(self):
        self.assertIn(URL, render())

    def test_status_note_is_shown(self):
        self.assertIn("安全を意味しません", render(skipped=[("dns", "empty")]))

    def test_finding_title_is_shown(self):
        self.assertIn("title", render(findings=[finding()]))

    def test_confidence_is_always_shown(self):
        self.assertIn("confidence: high", render(findings=[finding()]))

    def test_evidence_id_is_shown(self):
        self.assertIn("ev_1", render(findings=[finding(evidence=("ev_1",))]))


class TestEscaping(unittest.TestCase):

    def test_html_in_title_is_escaped(self):
        rendered = render(findings=[finding(title="<b>x</b>")])
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", rendered)
        self.assertNotIn("<b>x</b>", rendered)

    def test_html_in_subject_is_escaped(self):
        broken = finding()
        broken = Finding(
            id="f", rule_id="r", title="t", severity="LOW", confidence="high",
            subject="https://x.test/?a=<script>", message="m", why="w", fix="f", verify="v",
        )
        self.assertIn("&lt;script&gt;", render(findings=[broken]))


class TestSections(unittest.TestCase):

    def test_low_confidence_has_its_own_section(self):
        rendered = render(low_confidence=[finding(confidence="low")])
        self.assertIn("確度の低い所見", rendered)

    def test_review_badge_shows_the_count(self):
        rendered = render(skipped=[("dns", "empty"), ("ports", "empty")])
        self.assertIn('<span class="badge">2</span>', rendered)

    def test_empty_review_section_says_so(self):
        self.assertIn("実行できなかった項目はありません", render())

    def test_coverage_unknown_is_shown(self):
        self.assertIn("不明", render())

    def test_previous_difference_is_shown(self):
        rendered = render(previous={"overall": 10, "level": "LOW"})
        self.assertIn("差:", rendered)

    def test_no_previous_is_stated(self):
        self.assertIn("前回の診断がありません", render())


if __name__ == "__main__":
    unittest.main()