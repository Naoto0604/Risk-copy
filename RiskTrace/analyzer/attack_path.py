def generate_attack_paths(findings, correlations):
    """
    FindingとRisk Correlationから攻撃経路を生成する
    """

    attack_paths = []

    for correlation in correlations:

        correlation_type = correlation.get("type")
        url = correlation.get("url")

        if correlation_type != "COMBINED_RISK":
            continue

        related_findings = correlation.get("related_findings", [])
        related_finding_refs = [
            {
                "type": finding.get("type"),
                "subtype": finding.get("subtype"),
                "url": finding.get("url"),
                "title": finding.get("title"),
            }
            for finding in related_findings
            if isinstance(finding, dict)
        ]

        types = {
            finding.get("type")
            for finding in related_findings
        }

        # HTTPS + COOKIE
        if "HTTPS" in types and "COOKIE" in types:

            title = "通信保護不足からセッションリスクにつながる可能性"

            exists = any(
                path["url"] == url and path["title"] == title
                for path in attack_paths
            )

            if not exists:
                attack_paths.append({
                    "type": "ATTACK_PATH",
                    "severity": "HIGH",
                    "title": title,
                    "url": url,
                    "related_findings": related_finding_refs,
                    "steps": [
                        "HTTPS未使用",
                        "Cookie保護属性不足",
                        "セッション情報が危険にさらされる可能性",
                        "セッション悪用につながる可能性"
                    ],
                    "description":
                        "HTTPSが使用されておらず、"
                        "さらにCookieの保護属性にも不備があるため、"
                        "通信およびセッション保護に関する攻撃経路が成立する可能性があります。"
                })

        # HTTPS + SECURITY_HEADER
        if "HTTPS" in types and "SECURITY_HEADER" in types:

            title = "通信保護不足とブラウザ防御不足による攻撃リスク"

            exists = any(
                path["url"] == url and path["title"] == title
                for path in attack_paths
            )

            if not exists:
                attack_paths.append({
                    "type": "ATTACK_PATH",
                    "severity": "HIGH",
                    "title": title,
                    "url": url,
                    "related_findings": related_finding_refs,
                    "steps": [
                        "HTTPS未使用",
                        "セキュリティヘッダー不足",
                        "ブラウザ側の防御機構が不十分",
                        "Web攻撃につながる可能性"
                    ],
                    "description":
                        "HTTPSが使用されておらず、"
                        "さらにセキュリティヘッダーも不足しているため、"
                        "複数の防御機構が不足した状態となっています。"
                })

    return attack_paths
