"""RiskTrace priority scoring and display aggregation.

Keeps the existing RiskTrace priority scale while adding M8 CVE-candidate,
network-scope, confidence, and remediation-recommendation metadata.

Important: a CVE match based only on a remote banner is a triage candidate,
not proof that the installed product/build is vulnerable.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from collectors.explore.crawl import normalize_url

# Existing RiskTrace scale. CRITICAL is kept at 4 points for compatibility
# with the current priority tests; it is promoted to 最優先 as a special case.
# Legacy score scale retained for older callers / tests without evidence.
SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

PRIORITY_THRESHOLDS = {
    "最優先": 7,
    "高": 5,
    "中": 3,
}

# M8 score scale for evidence-backed production Findings.
M8_SEVERITY_SCORE = {
    "CRITICAL": 8.5,
    "HIGH": 7.0,
    "MEDIUM": 5.2,
    "LOW": 3.4,
    "INFO": 0.8,
}
M8_PRIORITY_THRESHOLDS = {
    "最優先": 8.5,
    "高": 6.5,
    "中": 3.5,
}

REVIEW_PORTS = {
    21, 22, 23, 25, 445, 587, 1433, 3306, 3389, 5432, 6379, 27017,
    3000, 5000, 8000, 8080, 8443,
}

PRODUCT_PORTS = {
    "mysql server": {3306},
    "openssh": {22},
    "apache http server": {80, 443, 8080, 8443},
    "redis": {6379},
    "ftp": {21},
    "smtp": {25, 587},
}

PORT_PRIORITY_REASONS = {
    21: "FTP用途に使われるポートです。実際のサービスは未確認のため、FTPの必要性と、必要な場合の暗号化方式を確認してください。",
    22: "SSHなどの管理用途に使われるポートです。実際のサービスは未確認のため、管理アクセスの必要性と接続元制限を確認してください。",
    23: "Telnet用途に使われるポートです。実際のサービスは未確認ですが、Telnetの場合は通信が暗号化されない可能性があるため、管理用途の必要性を確認してください。",
    25: "SMTP用途に使われるポートです。実際のサービスは未確認のため、メールサービスの公開範囲、認証、中継制限、TLS設定を確認してください。",
    587: "SMTP Submission用途に使われるポートです。実際のサービスは未確認のため、公開の必要性、認証、TLS、接続元制限を確認してください。",
    445: "SMB用途に使われるポートです。実際のサービスは未確認のため、ファイル共有の必要性と公開範囲を確認してください。",
    1433: "Microsoft SQL Server等のデータベース用途に使われるポートです。実際のサービスは未確認のため、接続元制限を確認してください。",
    3306: "MySQL等のデータベース用途に使われるポートです。実際のサービスは未確認のため、接続元制限を確認してください。",
    5432: "PostgreSQL等のデータベース用途に使われるポートです。実際のサービスは未確認のため、接続元制限を確認してください。",
    3389: "RDP用途に使われるポートです。実際のサービスは未確認のため、リモート管理の必要性と公開範囲を確認してください。",
    6379: "Redis等のデータストア用途に使われるポートです。実際のサービスは未確認のため、アクセス制御と接続元制限を確認してください。",
    27017: "MongoDB用途に使われるポートです。実際のサービスは未確認のため、公開範囲と認証を確認してください。",
    3000: "開発用Webサーバーで使われることがあるポートです。実際のサービスは未確認のため、開発用サービスの公開必要性を確認してください。",
    5000: "開発用Webサーバーで使われることがあるポートです。実際のサービスは未確認のため、開発用サービスの公開必要性を確認してください。",
    8000: "開発用Webサーバーで使われることがあるポートです。実際のサービスは未確認のため、開発用サービスの公開必要性を確認してください。",
    8080: "代替HTTP用途に使われることがあるポートです。実際のサービスは未確認のため、意図したWebサービスか、管理画面等が公開されていないか確認してください。",
    8443: "代替HTTPS用途に使われることがあるポートです。実際のサービスは未確認のため、意図したHTTPSサービスか、TLS設定と公開範囲を確認してください。",
}

CVSS_PATTERN = re.compile(
    r"(?:NVD CVSS base score|CVSS(?:\s+\d(?:\.\d)?)?\s+Base Score)\s*:\s*"
    r"([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
CVSS_SEVERITY_PATTERN = re.compile(
    r"(?:NVD CVSS severity|Base Score\s*:[^\n]*?\()\s*"
    r"(CRITICAL|HIGH|MEDIUM|LOW|NONE)\b",
    re.IGNORECASE,
)
CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
PORT_PATTERN = re.compile(r"(?:^|\n)Port:\s*(\d{1,5})\b", re.IGNORECASE)
SCOPE_PATTERN = re.compile(r"(?:^|\n)Network scope:\s*([A-Z_]+)", re.IGNORECASE)


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _safe_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number < 0 or number > 10:
        return None
    return number


def _cvss_score(finding: dict) -> float | None:
    evidence = _text(finding.get("evidence"))
    description = _text(finding.get("description"))
    for source in (evidence, description):
        match = CVSS_PATTERN.search(source)
        if match:
            return _safe_float(match.group(1))
    return _safe_float(finding.get("cvss_score"))


def _cvss_severity(finding: dict, cvss_score: float | None) -> str | None:
    evidence = _text(finding.get("evidence"))
    description = _text(finding.get("description"))
    for source in (evidence, description):
        match = CVSS_SEVERITY_PATTERN.search(source)
        if match:
            return match.group(1).upper()
    if cvss_score is None:
        return None
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    if cvss_score > 0:
        return "LOW"
    return "NONE"


def _is_cve_candidate(finding: dict) -> bool:
    if finding.get("type") != "VULNERABILITY_LOOKUP":
        return False
    subtype = _text(finding.get("subtype")).upper()
    if subtype and subtype != "CVE_VERSION_CANDIDATE":
        return False
    combined = f"{_text(finding.get('title'))}\n{_text(finding.get('evidence'))}"
    return bool(CVE_ID_PATTERN.search(combined))


def _observed_port(finding: dict) -> int | None:
    match = PORT_PATTERN.search(_text(finding.get("evidence")))
    if not match:
        return None
    try:
        port = int(match.group(1))
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _port_priority_reason(finding: dict) -> str | None:
    if finding.get("type") != "PORT_SCAN":
        return None
    port = _observed_port(finding)
    return PORT_PRIORITY_REASONS.get(port)


def _network_scope(finding: dict) -> str:
    match = SCOPE_PATTERN.search(_text(finding.get("evidence")))
    if not match:
        return "UNKNOWN"
    value = match.group(1).upper()
    if value in {"LOOPBACK", "PRIVATE", "PUBLIC", "LINK_LOCAL", "UNKNOWN"}:
        return value
    return "UNKNOWN"


def _product_name(finding: dict) -> str:
    combined = (
        f"{_text(finding.get('title')).lower()}\n"
        f"{_text(finding.get('evidence')).lower()}"
    )
    for name in ("mysql server", "apache http server", "openssh", "redis", "ftp", "smtp"):
        if name in combined:
            return name
    if "observed mysql server version string" in combined:
        return "mysql server"
    if "observed ssh banner" in combined:
        return "openssh"
    if "server header (unverified banner): apache/" in combined:
        return "apache http server"
    return ""


def _scope_for_finding(finding: dict, all_findings: list[dict]) -> str:
    direct_scope = _network_scope(finding)
    if direct_scope != "UNKNOWN":
        return direct_scope

    product = _product_name(finding)
    wanted_ports = PRODUCT_PORTS.get(product, set())
    url = finding.get("url")
    candidates: list[tuple[str, int | None]] = []

    for other in all_findings:
        if other is finding or other.get("type") != "PORT_SCAN":
            continue
        if url and other.get("url") != url:
            continue
        port = _observed_port(other)
        if wanted_ports and port not in wanted_ports:
            continue
        scope = _network_scope(other)
        if scope != "UNKNOWN":
            candidates.append((scope, port))

    if not candidates:
        return "UNKNOWN"
    for scope, port in candidates:
        if port in wanted_ports:
            return scope
    return candidates[0][0]


def _scope_adjustment(scope: str) -> tuple[float, str]:
    """Return a small context adjustment without claiming global reachability."""
    if scope == "PUBLIC":
        return 0.6, "検査元から接続した接続先IPはグローバルアドレスです。ただし、インターネット全域からの到達性を証明するものではありません。"
    if scope == "PRIVATE":
        return 0.2, "接続先IPはプライベートアドレスです。ネットワーク内での公開範囲を確認してください。"
    if scope == "LOOPBACK":
        return 0.0, "接続先はループバックアドレスです。別ホストや外部ネットワークからの到達性は示しません。"
    if scope == "LINK_LOCAL":
        return 0.1, "接続先IPはリンクローカルアドレスです。同一リンク内の到達範囲を確認してください。"
    return 0.0, "ネットワーク範囲は確認できていません。外部公開の有無は別途確認してください。"


def _is_reviewable_port_finding(finding: dict) -> bool:
    return finding.get("type") == "PORT_SCAN" and _observed_port(finding) in REVIEW_PORTS


def _related_to_correlation(finding: dict, correlations: list[dict]) -> bool:
    for correlation in correlations or []:
        for related in correlation.get("related_findings", []) or []:
            if not isinstance(related, dict):
                continue
            if related.get("type") != finding.get("type"):
                continue
            if related.get("url") != finding.get("url"):
                continue
            if "evidence" in finding and related.get("subtype") != finding.get("subtype"):
                continue
            related_title = related.get("title")
            if (
                ("evidence" in finding and related_title != finding.get("title"))
                or (related_title and related_title != finding.get("title"))
            ):
                continue
            return True
    return False


def _related_to_attack_path(finding: dict, attack_paths: list[dict]) -> bool:
    for path in attack_paths or []:
        rule_ids = path.get("rule_ids")
        if rule_ids and path.get("url") == finding.get("url"):
            if finding.get("rule_id") in rule_ids:
                return True
            continue        
        if path.get("url") != finding.get("url"):
            continue
        steps = path.get("steps", []) or []
        related_findings = path.get("related_findings")
        if related_findings:
            if any(
                isinstance(related, dict)
                and related.get("type") == finding.get("type")
                and related.get("url") == finding.get("url")
                and related.get("subtype") == finding.get("subtype")
                and related.get("title") == finding.get("title")
                for related in related_findings
            ):
                return True
            continue
        if not steps:
            continue

        finding_type = _text(finding.get("type"))
        severity = _text(finding.get("severity")).upper()
        if (
            finding_type == "HTTPS"
            and severity == "HIGH"
            and "HTTPS未使用" in steps
        ):
            return True
        if finding_type == "SECURITY_HEADER" and "セキュリティヘッダー不足" in steps:
            return True

        title = _text(finding.get("title"))
        if any(title and title in str(step) for step in steps):
            return True
    return False


def _recommendation(finding: dict, is_cve: bool, scope: str) -> str:
    existing = _text(finding.get("recommendation")).strip()
    if existing:
        return existing[:1200]
    if is_cve:
        return (
            "ベンダーのアドバイザリと実際のインストール済みビルドを確認し、"
            "該当が確認された場合は修正版への更新を計画してください。"
            "バナー由来のCVE候補だけで脆弱性を確定しないでください。"
        )
    if finding.get("type") == "PORT_SCAN":
        if scope == "LOOPBACK":
            return "ローカルで必要なサービスか確認してください。外部公開を示す結果ではありません。"
        if scope in {"PRIVATE", "PUBLIC"}:
            return "実際に待ち受けているサービスと公開の必要性を確認し、不要な場合は停止または接続元を制限してください。"
    if finding.get("type") == "TLS":
        return "証明書の有効期間、ホスト名、信頼チェーンを確認し、必要に応じて修正してください。"
    return "再現条件と影響範囲を確認し、ベンダーの推奨対策を適用してください。"


def _base_score(
    finding: dict,
    is_cve: bool,
    *,
    modern: bool,
) -> tuple[float, str, str, float | None]:
    severity = _text(finding.get("severity", "INFO")).upper()
    cvss_score = _cvss_score(finding) if is_cve else None

    if is_cve:
        # Banner-derived CVE matches remain triage candidates, not confirmed bugs.
        score = (cvss_score * 0.8) if cvss_score is not None else 2.0
        evidence = _text(finding.get("evidence"))
        description = _text(finding.get("description"))
        if "unverified" in evidence.lower() or "未検証" in description:
            score -= 1.5
        if re.search(r"CPE applicability status:\s*MATCH", evidence, re.IGNORECASE):
            score += 0.25
        rationale = (
            f"CVE候補です。NVD CVSS {cvss_score:.1f}"
            if cvss_score is not None
            else "CVE候補ですがCVSS基本スコアを取得できていません"
        )
        rationale += "。バナー由来の未検証情報なので、確認確度を考慮してスコアを減算しています。"
        return max(0.5, min(10.0, score)), rationale, "低（未検証バナー由来・インストール済みビルド未確認）", cvss_score

    if not modern:
        # Backward compatibility for callers which still pass the old, minimal
        # Finding shape without an evidence field.
        score = float(SEVERITY_SCORE.get(severity, 0))
        return score, f"検出時のSeverityは{severity}です。", "中（Findingの観測内容に基づく）", cvss_score

    if severity == "INFO" and not _is_reviewable_port_finding(finding):
        return 0.0, "情報提供のみで、現時点で優先対応の対象とはしていません。", "観測情報", cvss_score
    if severity == "INFO" and _is_reviewable_port_finding(finding):
        return 1.4, "管理・ファイル共有・データベース等に使われるポートへの接続を確認したため、必要性の確認を推奨します。", "低（TCP接続のみでサービスは未確認の場合があります）", cvss_score

    score = float(M8_SEVERITY_SCORE.get(severity, 0.8))
    return score, f"検出時のSeverityは{severity}です。", "中（Findingの観測内容に基づく。環境条件は別途確認）", cvss_score


def _priority_label(score: float, severity: str = "", *, modern: bool = False) -> str:
    if modern:
        if score >= M8_PRIORITY_THRESHOLDS["最優先"]:
            return "最優先"
        if score >= M8_PRIORITY_THRESHOLDS["高"]:
            return "高"
        if score >= M8_PRIORITY_THRESHOLDS["中"]:
            return "中"
        return "低"

    if severity == "CRITICAL" or score >= PRIORITY_THRESHOLDS["最優先"]:
        return "最優先"
    if score >= PRIORITY_THRESHOLDS["高"]:
        return "高"
    if score >= PRIORITY_THRESHOLDS["中"]:
        return "中"
    return "低"


def calculate_priority(findings, correlations, attack_paths):
    """Rank Findings using the current score scale and M8 evidence metadata.

    Evidence-backed Findings use the M8 model. Minimal legacy dictionaries
    without an ``evidence`` key retain the previous RiskTrace scoring behavior.
    """
    findings = [item for item in (findings or []) if isinstance(item, dict)]
    correlations = correlations or []
    attack_paths = attack_paths or []
    priorities = []

    for finding in findings:
        is_cve = _is_cve_candidate(finding)
        modern = "evidence" in finding
        base, rationale, confidence, cvss_score = _base_score(
            finding, is_cve, modern=modern
        )
        if base <= 0:
            continue

        severity = _text(finding.get("severity", "INFO")).upper()
        rationale = (
            _port_priority_reason(finding)
            or _text(finding.get("why"))
            or rationale
        )
        scope = _scope_for_finding(finding, findings)
        scope_bonus, scope_note = _scope_adjustment(scope)
        score = base + (scope_bonus if modern else 0.0)
        reasons = [rationale[:300], scope_note]
        if finding.get("confidence") == "medium":
            reasons.append("確度は中程度です。")
        elif finding.get("confidence") == "low":
            reasons.append("確度は低めです。")

        if _related_to_correlation(finding, correlations):
            score += 0.5 if modern else 2
            reasons.append("複合リスク分析の関連Findingに含まれています。")

        if _related_to_attack_path(finding, attack_paths):
            if modern:
                score += 0.5
            elif (
                finding.get("type") == "HTTPS"
                and severity == "HIGH"
                and any(
                    path.get("url") == finding.get("url")
                    and "HTTPS未使用" in (path.get("steps", []) or [])
                    for path in attack_paths
                )
            ):
                score += 3
            elif (
                finding.get("type") == "SECURITY_HEADER"
                and any(
                    path.get("url") == finding.get("url")
                    and "セキュリティヘッダー不足" in (path.get("steps", []) or [])
                    for path in attack_paths
                )
            ):
                score += 1
            reasons.append("攻撃経路分析に関連するため、優先度を加算しています。")

        score = round(max(0.0, min(10.0, score)), 2)
        label = _priority_label(score, severity, modern=modern)
        recommendation = _recommendation(finding, is_cve, scope)
        original_description = _text(finding.get("description"))
        display_description = original_description
        display_description += f"\n\n優先理由：{' '.join(reasons)}"
        display_description += f"\n確認確度：{confidence}"
        display_description += f"\n推奨対応：{recommendation}"

        priorities.append({
            "rule_id": finding.get("rule_id"),
            "type": finding.get("type"),
            "subtype": finding.get("subtype"),
            "title": finding.get("title"),
            "severity": severity,
            "url": finding.get("url"),
            "evidence": finding.get("evidence"),
            "finding": deepcopy(finding),
            "priority_score": score,
            "priority": label,
            "description": display_description,
            "original_description": original_description,
            "priority_reason": " ".join(reasons),
            "confidence": confidence,
            "network_scope": scope,
            "confidence_raw": finding.get("confidence"),
            "cvss_score": cvss_score,
            "cvss_severity": _cvss_severity(finding, cvss_score) if is_cve else None,
            "recommended_action": recommendation,
            "is_cve_candidate": is_cve,
        })

    confidence_rank = {"high": 2, "medium": 1, "low": 0}
    priorities.sort(
        key=lambda item: (
            item["priority_score"],
            confidence_rank.get(item.get("confidence_raw") or "", 0),
            item.get("cvss_score") or 0.0,
            item.get("title") or "",
        ),
        reverse=True,
    )
    return priorities


def aggregate_priorities(priorities):
    """Group individual priority records for display without mutating them."""
    severity_rank = {
        "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
    }
    grouped = {}
    for item in priorities or []:
        category = item.get("category") or item.get("type")
        subtype = item.get("subtype") or ""
        normalized_title = " ".join(
            re.sub(r"\s+", " ", str(item.get("title") or "")).split()
        ).casefold()
        recommendation = " ".join(
            str(item.get("recommended_action") or "").split()
        ).casefold()
        key = (category, subtype, normalized_title, recommendation)
        group = grouped.get(key)
        if group is None:
            group = dict(item)
            group.update({
                "category": category,
                "finding_count": 0,
                "page_count": 0,
                "affected_urls": [],
                "findings": [],
                "_url_keys": set(),
            })
            grouped[key] = group

        # Each original priority record and its original Finding stay available
        # in the expanded details. Never rewrite the source record.
        group["findings"].append(item)
        group["finding_count"] += 1
        url = item.get("url")
        url_key = normalize_url(url) if isinstance(url, str) else None
        url_key = url_key or url
        if url and url_key not in group["_url_keys"]:
            group["_url_keys"].add(url_key)
            group["affected_urls"].append(url)

        current_risk = (
            item.get("priority_score", 0),
            severity_rank.get(str(item.get("severity", "INFO")).upper(), 0),
            item.get("cvss_score") or 0,
        )
        representative_risk = (
            group.get("priority_score", 0),
            severity_rank.get(str(group.get("severity", "INFO")).upper(), 0),
            group.get("cvss_score") or 0,
        )
        if current_risk > representative_risk:
            for field, value in item.items():
                if field not in {"finding", "evidence"}:
                    group[field] = value

    result = list(grouped.values())
    for group in result:
        group["page_count"] = len(group["_url_keys"])
        del group["_url_keys"]
        group["affected_urls"].sort()
    result.sort(
        key=lambda item: (
            item.get("priority_score", 0),
            severity_rank.get(str(item.get("severity", "INFO")).upper(), 0),
            item.get("cvss_score") or 0,
            item.get("title") or "",
        ),
        reverse=True,
    )
    return result


#: rule_id の接頭辞から v1 の type へ戻す対応。
CATEGORY_TYPES = {
    "headers": "SECURITY_HEADER",
    "cookies": "COOKIE",
    "tls": "TLS",
    "ports": "PORT_SCAN",
    "cve": "VULNERABILITY_LOOKUP",
    "transport": "HTTPS",
    "redirects": "REDIRECT",
    "dns": "DNS",
    "explore": "EXPLORE",
    "baas": "BAAS",
    "corr": "CORRELATION",
}


def _legacy_dict(finding) -> dict:
    """v2 の Finding を、既存の採点が読む辞書へ写す。"""
    prefix = finding.rule_id.split(":", 1)[0].split(".", 1)[0]
    observed = finding.observed or {}
    return {
        "type": CATEGORY_TYPES.get(prefix, "OTHER"),
        "rule_id": finding.rule_id,
        "subtype": observed.get("subtype") or finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "url": finding.subject,
        "description": finding.message,
        "why": finding.why,
        "confidence": finding.confidence,
        "evidence": finding.why,
        "recommendation": finding.fix,
    }


def priority_rows(findings, paths=()) -> list[dict]:
    """v2 の Finding 群から優先度の行を作る。"""
    attack_paths = [
        {"url": path.subject, "rule_ids": list(path.rule_ids), "steps": list(path.steps)}
        for path in paths or ()
    ]
    return calculate_priority(
        [_legacy_dict(item) for item in findings or []], [], attack_paths
    )