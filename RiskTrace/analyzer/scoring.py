SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

from scanner.crawler import normalize_url

def calculate_risk_score(findings):
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

        url_scores[url] = max(
            url_scores[url],
            score
        )

    total_score = sum(url_scores.values())

    risk_score = int(
    (total_score / len(url_scores)) * 25
    )

    return risk_score

def get_risk_level(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"
