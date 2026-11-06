"""v1 形式の finding 辞書を採点する互換層。

v2 は ``analyzer/scoring_v2.py`` の3軸式を使う。こちらは v1 の画面が
前提にしている「URL ごとの最大 severity の平均」をそのまま保つ。
"""

from __future__ import annotations

from engine.legacy_crawl import normalize_url

SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def calculate_risk_score(findings) -> int:
    """URL ごとの最大 severity を平均し、25 倍した 0..100。"""
    if not findings:
        return 0

    url_scores = {}

    for finding in findings:
        url = finding.get("url")
        normalized_url = normalize_url(url) if isinstance(url, str) else None
        if normalized_url:
            url = normalized_url
        severity = finding.get("severity", "INFO")
        score = SEVERITY_SCORE.get(severity, 0)

        if url not in url_scores:
            url_scores[url] = 0

        url_scores[url] = max(url_scores[url], score)

    total_score = sum(url_scores.values())

    return int((total_score / len(url_scores)) * 25)


def get_risk_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"