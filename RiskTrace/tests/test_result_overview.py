import unittest

from app import build_risk_map, summarize_findings


class TestResultOverview(unittest.TestCase):
    def test_critical_pages_are_included_in_high_risk_count(self):
        findings = [
            {"url": "https://example.test/a", "severity": "CRITICAL"},
            {"url": "https://example.test/b", "severity": "HIGH"},
            {"url": "https://example.test/c", "severity": "MEDIUM"},
            {"url": "https://example.test/d", "severity": "LOW"},
        ]
        risk_map = build_risk_map(
            "https://example.test/",
            [finding["url"] for finding in findings],
            findings,
            [],
        )
        self.assertEqual(risk_map["summary"]["high_risk_pages"], 2)
        self.assertEqual(risk_map["summary"]["medium_risk_pages"], 1)

    def test_same_finding_kind_is_summarized_by_distinct_pages(self):
        findings = [
            {
                "type": "SECURITY_HEADER",
                "subtype": "Content-Security-Policy",
                "severity": "MEDIUM",
                "title": "CSPが設定されていません",
                "url": "https://example.test/a",
                "evidence": "header absent",
            },
            {
                "type": "SECURITY_HEADER",
                "subtype": "Content-Security-Policy",
                "severity": "MEDIUM",
                "title": "CSPが設定されていません",
                "url": "https://example.test/b",
                "evidence": "header absent",
            },
            {
                "type": "SECURITY_HEADER",
                "subtype": "X-Frame-Options",
                "severity": "MEDIUM",
                "title": "X-Frame-Optionsが設定されていません",
                "url": "https://example.test/a",
                "evidence": "header absent",
            },
        ]
        summaries = summarize_findings(findings)
        csp = next(item for item in summaries if item["subtype"] == "Content-Security-Policy")
        xfo = next(item for item in summaries if item["subtype"] == "X-Frame-Options")

        self.assertEqual(csp["finding_count"], 2)
        self.assertEqual(csp["page_count"], 2)
        self.assertEqual(xfo["finding_count"], 1)
        self.assertEqual(xfo["page_count"], 1)
        self.assertEqual(len(findings), 3)  # input records remain unchanged


if __name__ == "__main__":
    unittest.main()
