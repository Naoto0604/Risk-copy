def correlate_findings(findings):

    correlations = []

    urls = {}

    for finding in findings:
        url = finding.get("url")

        if not url:
            continue

        if url not in urls:
            urls[url] = []

        urls[url].append(finding)

    for url, url_findings in urls.items():

        types = {
            finding.get("type")
            for finding in url_findings
        }



        https_finding = next(
            (
                finding for finding in url_findings
                if finding.get("type") == "HTTPS"
                and finding.get("severity") == "HIGH"
            ),
            None
        )
        # HTTPS + COOKIE
        if https_finding and "COOKIE" in types:
            cookie_findings = [
                finding for finding in url_findings
                if finding.get("type") == "COOKIE"
            ]

            correlations.append({
                "type": "COMBINED_RISK",
                "severity": "HIGH",
                "title": "HTTPS未使用とCookie設定不備の複合リスク",
                "url": url,
                "related_findings": [
                    https_finding,
                    *cookie_findings
                ],
                "description":
                    "HTTPSが使用されていない状態でCookieの保護属性にも不備があるため、"
                    "通信およびセッション保護に関する複合的なリスクがあります。"
            })

        # HTTPS + SECURITY_HEADER
        if https_finding and "SECURITY_HEADER" in types:
            header_findings = [
                finding for finding in url_findings
                if finding.get("type") == "SECURITY_HEADER"
            ]

            correlations.append({
                "type": "COMBINED_RISK",
                "severity": "HIGH",
                "title": "HTTPS未使用とセキュリティヘッダー不足の複合リスク",
                "url": url,
                "related_findings": [
                    https_finding,
                    *header_findings
                ],
                "description":
                    "HTTPSが使用されておらず、さらにセキュリティヘッダーも不足しているため、"
                    "通信保護とブラウザ側の防御機構が十分でない可能性があります。"
            })

    return correlations