import re
from urllib.parse import urlparse, urljoin


def check_https(url):
    """URLがHTTPSを使用しているか確認する。"""
    parsed_url = urlparse(url)

    if parsed_url.scheme.lower() == "https":
        return {
            "type": "HTTPS",
            "severity": "INFO",
            "title": "HTTPSが使用されています",
            "url": url,
            "description": "通信にHTTPSが使用されています。",
        }

    return {
        "type": "HTTPS",
        "severity": "HIGH",
        "title": "HTTPSが使用されていません",
        "url": url,
        "description": "HTTP通信では通信内容が暗号化されません。",
    }


def check_security_headers(response):
    """主要なセキュリティヘッダーの設定状況を確認する。"""
    findings = []

    security_headers = {
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "X-Frame-Options",
        "Referrer-Policy": "Referrer-Policy",
    }

    # HTTPヘッダー名は大文字・小文字を区別せず比較する
    existing_headers = {
        header.lower()
        for header in response.headers
    }

    for header, name in security_headers.items():
        if header.lower() not in existing_headers:
            findings.append({
                "type": "SECURITY_HEADER",
                "subtype": header,
                "severity": "MEDIUM",
                "title": f"{name}が設定されていません",
                "url": response.url,
                "description": (
                    f"{header}ヘッダーが確認できませんでした。"
                ),
            })

    # HTTPSの場合のみHSTSを確認する
    if urlparse(response.url).scheme.lower() == "https":
        if "strict-transport-security" not in existing_headers:
            findings.append({
                "type": "SECURITY_HEADER",
                "subtype": "Strict-Transport-Security",
                "severity": "MEDIUM",
                "title": "HSTSが設定されていません",
                "url": response.url,
                "description": (
                    "Strict-Transport-Securityヘッダーが"
                    "確認できませんでした。"
                ),
            })

    return findings


REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308,
}


def check_http_redirect(response):
    """HTTPリダイレクトの経路を確認する。"""
    findings = []

    redirect_history = getattr(response, "history", [])

    if not redirect_history:
        return findings

    redirect_chain = []
    external_redirect = False

    for redirect_response in redirect_history:
        status_code = redirect_response.status_code

        if status_code not in REDIRECT_STATUS_CODES:
            continue

        source_url = redirect_response.url
        location = redirect_response.headers.get("Location")

        if not location:
            continue

        destination_url = urljoin(source_url, location)

        source_host = urlparse(source_url).netloc
        destination_host = urlparse(destination_url).netloc

        if source_host.lower() != destination_host.lower():
            external_redirect = True

        redirect_chain.append({
            "status_code": status_code,
            "from": source_url,
            "to": destination_url,
        })

    if not redirect_chain:
        return findings

    if external_redirect:
        severity = "LOW"
        title = "外部ドメインへのHTTPリダイレクトが検出されました"
        description = (
            "HTTPリダイレクトによって外部ドメインへの遷移が"
            "確認されました。"
            "正当な認証・決済などでも発生するため、"
            "意図した遷移か確認してください。"
        )
    else:
        severity = "INFO"
        title = "HTTPリダイレクトが検出されました"
        description = (
            "HTTPリダイレクトが確認されました。"
            "リダイレクト先と遷移経路を確認してください。"
        )

    chain_text = []

    for redirect in redirect_chain:
        chain_text.append(
            f'{redirect["status_code"]}: '
            f'{redirect["from"]} -> {redirect["to"]}'
        )

    findings.append({
        "type": "REDIRECT",
        "subtype": "HTTP_REDIRECT",
        "severity": severity,
        "title": title,
        "url": redirect_chain[0]["from"],
        "description": description,
        "evidence": (
            "\n".join(chain_text)
            + f"\nFinal URL: {response.url}"
        ),
    })

    return findings


def check_meta_refresh(url, response):
    """HTMLのMeta Refreshによる自動遷移を検出する。"""
    findings = []

    meta_tags = re.findall(
        r"<meta\b[^>]*>",
        response.text,
        re.IGNORECASE,
    )

    for meta_tag in meta_tags:
        http_equiv = re.search(
            r"""\bhttp-equiv\s*=\s*(?:"refresh"|'refresh'|refresh)(?=\s|/?>)""",
            meta_tag,
            re.IGNORECASE,
        )

        if not http_equiv:
            continue

        content_match = re.search(
            r"""\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
            meta_tag,
            re.IGNORECASE,
        )

        if not content_match:
            continue

        content = next(
            (
                value
                for value in content_match.groups()
                if value is not None
            ),
            "",
        )

        url_match = re.search(
            r"(?:^|;)\s*url\s*=\s*(.+?)\s*$",
            content,
            re.IGNORECASE,
        )

        if not url_match:
            continue

        destination = url_match.group(1).strip().strip("'\"")

        if not destination:
            continue

        destination_url = urljoin(response.url, destination)

        source_host = urlparse(response.url).netloc
        destination_host = urlparse(destination_url).netloc

        if source_host.lower() != destination_host.lower():
            severity = "LOW"
            title = "外部ドメインへのMeta Refreshが検出されました"
            description = (
                "HTMLのMeta Refreshによって外部ドメインへの"
                "遷移が確認されました。"
                "意図した遷移か確認してください。"
            )
        else:
            severity = "INFO"
            title = "Meta Refreshが検出されました"
            description = (
                "HTMLのMeta Refreshによる自動遷移が確認されました。"
                "遷移先と設定内容を確認してください。"
            )

        findings.append({
            "type": "REDIRECT",
            "subtype": "META_REFRESH",
            "severity": severity,
            "title": title,
            "url": response.url,
            "description": description,
            "evidence": (
                f"Meta Refresh: {response.url} -> {destination_url}\n"
                f"Content: {content}"
            ),
        })

        # 1ページにつき1件にまとめる
        break

    return findings


def check_js_redirect(url, response):
    """HTML内のJavaScriptによるリダイレクトを検出する。"""
    findings = []

    script_blocks = re.findall(
        r"<script\b[^>]*>(.*?)</script>",
        response.text,
        re.IGNORECASE | re.DOTALL,
    )

    patterns = [
        r"""(?:window\.)?location\.href\s*=\s*['"]([^'"]+)['"]""",
        r"""(?:window\.)?location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)""",
        r"""(?:window\.)?location\s*=\s*['"]([^'"]+)['"]""",
    ]

    for script in script_blocks:
        for pattern in patterns:
            match = re.search(pattern, script, re.IGNORECASE)

            if not match:
                continue

            destination = match.group(1).strip()
            destination_url = urljoin(response.url, destination)

            source_host = urlparse(response.url).netloc
            destination_host = urlparse(destination_url).netloc

            if source_host.lower() != destination_host.lower():
                severity = "LOW"
                title = (
                    "外部ドメインへのJavaScriptリダイレクトが"
                    "検出されました"
                )
                description = (
                    "JavaScriptによって外部ドメインへの自動遷移が"
                    "確認されました。"
                    "意図した遷移か確認してください。"
                )
            else:
                severity = "INFO"
                title = "JavaScriptリダイレクトが検出されました"
                description = (
                    "JavaScriptによる自動遷移が確認されました。"
                    "遷移先とスクリプトの内容を確認してください。"
                )

            findings.append({
                "type": "REDIRECT",
                "subtype": "JS_REDIRECT",
                "severity": severity,
                "title": title,
                "url": response.url,
                "description": description,
                "evidence": (
                    f"JavaScript Redirect: "
                    f"{response.url} -> {destination_url}\n"
                    f"Script: {script.strip()}"
                ),
            })

            # 1ページにつき1件にまとめる
            return findings

    return findings


_COOKIE_NAME_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_DELIMITER = re.compile(r"\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+\s*=")
_SENSITIVE_COOKIE_NAMES = re.compile(
    r"^(?:session|sessionid|sid|phpsessid|jsessionid|connect\.sid|"
    r"laravel_session|asp\.net_sessionid|ci_session|auth|auth_token|"
    r"access_token|refresh_token|jwt|wordpress_logged_in(?:_.+)?)$",
    re.IGNORECASE,
)


def _split_set_cookie_field(value):
    """Split a coalesced Set-Cookie field only at cookie-pair delimiters.

    Expires dates contain a comma, but the text after that comma is not a
    cookie-pair. Quoted values are also kept intact. This is deliberately not
    a plain comma split.
    """
    parts = []
    start = 0
    quote = None
    escaped = False
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char == "," and _COOKIE_DELIMITER.match(value, index + 1):
            part = value[start:index].strip()
            if not part:
                return []
            parts.append(part)
            start = index + 1
    tail = value[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _get_set_cookie_headers(response):
    """Get individual Set-Cookie values, conservatively handling fallbacks."""
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)

    for method_name in ("getlist", "get_all"):
        method = getattr(raw_headers, method_name, None)
        if not callable(method):
            continue
        try:
            values = method("Set-Cookie")
        except (KeyError, TypeError, ValueError):
            values = None
        if values:
            result = []
            for value in values:
                if not value:
                    continue
                split_values = _split_set_cookie_field(str(value))
                if not split_values:
                    return []
                result.extend(split_values)
            return result

    headers = getattr(response, "headers", None)
    get_header = getattr(headers, "get", None)
    value = get_header("Set-Cookie") if callable(get_header) else None
    if not value:
        return []
    # A plain mapping cannot prove whether repeated headers were coalesced.
    # Accept only cookie-pairs that can be separated without splitting Expires.
    return _split_set_cookie_field(str(value))


def _split_cookie_segments(cookie_header):
    """Split a Set-Cookie string on unquoted semicolons."""
    segments = []
    start = 0
    quote = None
    escaped = False
    for index, char in enumerate(cookie_header):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == ";":
            segments.append(cookie_header[start:index].strip())
            start = index + 1
    segments.append(cookie_header[start:].strip())
    return segments


def _parse_cookie(cookie_header, reference):
    """Parse metadata needed for checks without returning/storing the value."""
    segments = _split_cookie_segments(cookie_header)
    if not segments or "=" not in segments[0]:
        return None

    name, _separator, _value = segments[0].partition("=")
    name = name.strip()
    if not _COOKIE_NAME_TOKEN.fullmatch(name):
        return None

    attributes = {}
    for segment in segments[1:]:
        if not segment:
            continue
        attribute_name, separator, attribute_value = segment.partition("=")
        attribute_name = attribute_name.strip().lower()
        if not attribute_name:
            continue
        attributes[attribute_name] = (
            attribute_value.strip().strip("'\"") if separator else None
        )

    same_site_raw = attributes.get("samesite")
    same_site = None
    same_site_valid = None
    if "samesite" in attributes:
        normalized = (same_site_raw or "").lower()
        same_site_valid = normalized in {"strict", "lax", "none"}
        same_site = normalized.capitalize() if same_site_valid else "invalid"

    sensitive = bool(_SENSITIVE_COOKIE_NAMES.fullmatch(name))
    return {
        "reference": reference,
        "sensitive_candidate": sensitive,
        "purpose": (
            "セッション・認証関連の可能性（名前からの推定）"
            if sensitive else "用途不明（名前から用途を確定できず）"
        ),
        "confidence": (
            "中（既知の名前パターンに一致。用途は未確認）"
            if sensitive else "低（Cookie名だけでは用途を特定できない）"
        ),
        "httponly": "httponly" in attributes,
        "secure": "secure" in attributes,
        "same_site": same_site,
        "same_site_valid": same_site_valid,
        "domain": "domain" in attributes,
        "path": "path" in attributes,
        "expiration": "expires" in attributes or "max-age" in attributes,
    }


def _cookie_attribute_evidence(cookie):
    """Create safe evidence without disclosing cookie names or values."""
    same_site = cookie["same_site"] or "missing"
    return (
        f'{cookie["reference"]}: HttpOnly={"present" if cookie["httponly"] else "missing"}; '
        f'Secure={"present" if cookie["secure"] else "missing"}; '
        f'SameSite={same_site}; Domain={"present" if cookie["domain"] else "absent"}; '
        f'Path={"present" if cookie["path"] else "absent"}; '
        f'Expires/Max-Age={"present" if cookie["expiration"] else "absent"}; '
        f'用途={cookie["purpose"]}; 用途推定の確度={cookie["confidence"]}'
    )


def check_cookies(response):
    """Assess each Set-Cookie independently, without retaining cookie values."""
    cookie_headers = _get_set_cookie_headers(response)
    if not cookie_headers:
        return []

    parsed_cookies = [
        cookie
        for index, header in enumerate(cookie_headers, start=1)
        if (cookie := _parse_cookie(header, f"Cookie #{index}")) is not None
    ]
    if not parsed_cookies:
        return []

    is_https = urlparse(response.url).scheme.lower() == "https"
    issues = []

    def add_issue(cookie, subtype, title, severity, reason, recommendation):
        issues.append({
            "type": "COOKIE",
            "subtype": subtype,
            "severity": severity,
            "title": title,
            "url": response.url,
            "description": (
                f"{reason} 用途はCookie名からの推定であり、実際の用途は未確認です。"
            ),
            "evidence": _cookie_attribute_evidence(cookie),
            "recommendation": recommendation,
        })

    for cookie in parsed_cookies:
        auth_candidate = cookie["sensitive_candidate"]
        confidence_note = cookie["confidence"]
        review_severity = "MEDIUM" if auth_candidate else "LOW"

        if not cookie["httponly"]:
            add_issue(
                cookie,
                "COOKIE_HTTPONLY_MISSING",
                "HttpOnly属性が設定されていません",
                review_severity,
                "HttpOnlyがないためJavaScriptからCookieを読める可能性があります。"
                f"{cookie['purpose']}。{confidence_note}。",
                "Cookieの用途を確認し、ブラウザーJavaScriptから読む必要がなければHttpOnlyを設定してください。",
            )

        same_site_none_without_secure = (
            cookie["same_site"] == "None" and not cookie["secure"]
        )
        if same_site_none_without_secure:
            add_issue(
                cookie,
                "COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
                "SameSite=NoneのCookieにSecureが設定されていません",
                review_severity,
                "SameSite=NoneにはSecureの併用が必要です。"
                f"{cookie['purpose']}。{confidence_note}。",
                "SameSite=Noneが必要な設計か確認し、必要であればSecureを設定してHTTPSで配信してください。",
            )
        elif is_https and not cookie["secure"]:
            add_issue(
                cookie,
                "COOKIE_SECURE_MISSING",
                "Secure属性が設定されていません",
                review_severity,
                "HTTPSレスポンスで発行されたCookieにSecureがありません。"
                f"{cookie['purpose']}。{confidence_note}。",
                "Cookieの送信範囲を確認し、HTTPS専用にするCookieにはSecureを設定してください。",
            )

        if cookie["same_site"] is None:
            add_issue(
                cookie,
                "COOKIE_SAMESITE_MISSING",
                "SameSite属性が設定されていません",
                review_severity,
                "SameSiteが明示されていません。ブラウザーの既定動作は環境により異なる場合があります。"
                f"{cookie['purpose']}。{confidence_note}。",
                "Cookieのクロスサイト利用要件を確認し、必要に応じてLaxまたはStrictを設定してください。",
            )
        elif cookie["same_site_valid"] is False:
            add_issue(
                cookie,
                "COOKIE_SAMESITE_INVALID",
                "SameSite属性の値が不正です",
                review_severity,
                "SameSiteの値がStrict、Lax、Noneのいずれでもありません。"
                f"{cookie['purpose']}。{confidence_note}。",
                "SameSiteをStrict、Lax、Noneのいずれかにし、Noneの場合はSecureも設定してください。",
            )

    return issues


def run_checks(url, response, enabled_checks=None):
    """
    選択された診断項目を実行する。

    enabled_checks:
        https     - HTTPSチェック
        headers   - セキュリティヘッダーチェック
        cookies   - Cookieチェック
        redirects - HTTP / Meta Refresh / JavaScriptリダイレクト

    Noneの場合は、すべての診断項目を実行する。
    """
    if enabled_checks is None:
        enabled_checks = {
            "https",
            "headers",
            "cookies",
            "redirects",
        }
    else:
        enabled_checks = set(enabled_checks)

    findings = []

    # HTTPS
    if "https" in enabled_checks:
        findings.append(check_https(url))

    # Security Headers
    if "headers" in enabled_checks:
        findings.extend(check_security_headers(response))

    # Cookies
    if "cookies" in enabled_checks:
        findings.extend(check_cookies(response))

    # Redirect関連の診断
    if "redirects" in enabled_checks:
        findings.extend(check_http_redirect(response))
        findings.extend(check_meta_refresh(url, response))
        findings.extend(check_js_redirect(url, response))

    return findings
