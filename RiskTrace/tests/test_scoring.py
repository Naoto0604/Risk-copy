import unittest

from engine.legacy_scoring import (
    SEVERITY_SCORE,
    calculate_risk_score,
    get_risk_level,
)


class TestCalculateRiskScore(unittest.TestCase):

    def test_empty_findings_returns_zero(self):
        """Findingが空の場合は0点。"""
        self.assertEqual(calculate_risk_score([]), 0)

    def test_each_severity_has_expected_score(self):
        """各Severityが仕様どおりのスコアになる。"""
        expected_scores = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
            "INFO": 0,
        }

        for severity, expected in expected_scores.items():
            with self.subTest(severity=severity):
                findings = [{
                    "url": "http://example.test/",
                    "severity": severity,
                }]

                self.assertEqual(
                    calculate_risk_score(findings),
                    expected,
                )

    def test_multiple_findings_on_same_url_use_highest_severity(self):
        """同一URLでは最高Severityだけを採用する。"""
        findings = [
            {
                "url": "http://example.test/",
                "severity": "HIGH",
            },
            {
                "url": "http://example.test/",
                "severity": "MEDIUM",
            },
            {
                "url": "http://example.test/",
                "severity": "LOW",
            },
        ]

        self.assertEqual(calculate_risk_score(findings), 75)

    def test_canonical_url_variants_are_one_score_input(self):
        findings = [
            {"url": "https://example.test/contact/?topic=日本語#top", "severity": "HIGH"},
            {"url": "https://EXAMPLE.test/contact/?topic=%E6%97%A5%E6%9C%AC%E8%AA%9E", "severity": "INFO"},
        ]
        self.assertEqual(calculate_risk_score(findings), 75)

    def test_score_averages_severity_across_urls(self):
        """複数URLの最高Severityの平均を使う。"""
        findings = [
            {
                "url": "http://example.test/",
                "severity": "HIGH",
            },
            {
                "url": "http://example.test/about",
                "severity": "LOW",
            },
        ]

        # (HIGH 3 + LOW 1) / 2 * 25 = 50
        self.assertEqual(calculate_risk_score(findings), 50)

    def test_unknown_severity_contributes_zero(self):
        """未定義のSeverityは0点として扱う。"""
        findings = [{
            "url": "http://example.test/",
            "severity": "UNKNOWN",
        }]

        self.assertEqual(calculate_risk_score(findings), 0)

    def test_score_stays_between_zero_and_one_hundred(self):
        """通常のSeverityの組み合わせで0〜100に収まる。"""
        findings = [
            {
                "url": f"http://example.test/{index}",
                "severity": "CRITICAL",
            }
            for index in range(5)
        ]

        score = calculate_risk_score(findings)

        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertEqual(score, 100)


class TestGetRiskLevel(unittest.TestCase):

    def test_risk_level_boundaries(self):
        """リスクレベルの境界値が正しい。"""
        cases = [
            (0, "LOW"),
            (29, "LOW"),
            (30, "MEDIUM"),
            (69, "MEDIUM"),
            (70, "HIGH"),
            (89, "HIGH"),
            (90, "CRITICAL"),
            (100, "CRITICAL"),
        ]

        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(
                    get_risk_level(score),
                    expected,
                )

    def test_single_severity_maps_to_matching_risk_level(self):
        cases = [
            ("INFO", 0, "LOW"),
            ("LOW", 25, "LOW"),
            ("MEDIUM", 50, "MEDIUM"),
            ("HIGH", 75, "HIGH"),
            ("CRITICAL", 100, "CRITICAL"),
        ]
        for severity, expected_score, expected_level in cases:
            with self.subTest(severity=severity):
                score = calculate_risk_score([{
                    "url": "https://example.test/",
                    "severity": severity,
                }])
                self.assertEqual(score, expected_score)
                self.assertEqual(get_risk_level(score), expected_level)

    def test_multi_url_average_uses_aligned_risk_level(self):
        findings = [
            {"url": "https://example.test/a", "severity": "HIGH"},
            {"url": "https://example.test/b", "severity": "LOW"},
        ]
        score = calculate_risk_score(findings)
        self.assertEqual(score, 50)
        self.assertEqual(get_risk_level(score), "MEDIUM")


if __name__ == "__main__":
    unittest.main()
