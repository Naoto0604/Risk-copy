"""v1 の結果画面用の整形。

Risk Map の組み立てと概要の集約だけを行う。判定はしない。
"""

from __future__ import annotations

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def get_highest_severity(findings):
    """Finding 一覧から最も高い Severity を返す。"""
    if not findings:
        return "INFO"

    highest = "INFO"
    for finding in findings:
        severity = finding.get("severity", "INFO")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = severity
    return highest


def build_risk_map(target_url, discovered_urls, findings, correlations):
    """Risk Map 表示用のデータを作る。"""
    findings_by_url = {}
    for finding in findings:
        finding_url = finding.get("url")
        if not finding_url:
            continue
        findings_by_url.setdefault(finding_url, []).append(finding)

    urls = set()
    if target_url:
        urls.add(target_url)
    for discovered_url in discovered_urls or ():
        urls.add(discovered_url)
    for finding_url in findings_by_url:
        urls.add(finding_url)

    pages = []
    for page_url in sorted(urls):
        page_findings = findings_by_url.get(page_url, [])
        pages.append({
            "url": page_url,
            "findings": page_findings,
            "severity": get_highest_severity(page_findings),
        })

    risk_correlations = []
    for correlation in correlations or ():
        risk_correlations.append({
            "title": correlation.get("title"),
            "severity": correlation.get("severity", "HIGH"),
            "url": correlation.get("url"),
            "description": correlation.get("description"),
        })

    return {
        "target_url": target_url,
        "pages": pages,
        "correlations": risk_correlations,
        "summary": {
            "high_risk_pages": sum(
                page["severity"] in {"HIGH", "CRITICAL"} for page in pages
            ),
            "medium_risk_pages": sum(
                page["severity"] == "MEDIUM" for page in pages
            ),
        },
    }


def summarize_findings(findings):
    """概要行を種別ごとにまとめる。生の Finding は保持する。"""
    grouped = {}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        key = (
            finding.get("type") or "UNKNOWN",
            finding.get("subtype") or "",
            finding.get("title") or "Untitled finding",
            (finding.get("severity") or "INFO").upper(),
        )
        summary = grouped.setdefault(key, {
            "type": key[0],
            "subtype": key[1],
            "title": key[2],
            "severity": key[3],
            "finding_count": 0,
            "urls": {},
        })
        summary["finding_count"] += 1
        url = finding.get("url")
        if url:
            summary["urls"][url] = summary["urls"].get(url, 0) + 1

    summaries = []
    for summary in grouped.values():
        summary["page_count"] = len(summary["urls"])
        summary["page_details"] = [
            {"url": url, "finding_count": count}
            for url, count in sorted(summary["urls"].items())
        ]
        summaries.append(summary)
    return sorted(
        summaries,
        key=lambda item: (
            -item["finding_count"], item["title"], item["type"], item["subtype"]
        ),
    )