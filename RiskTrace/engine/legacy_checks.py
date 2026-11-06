import re
from pathlib import Path

from collectors.http import cookies as cookies_collector
from engine import rule_runner
from engine.observations import Observation
from engine.rules import load_rules_from_dir
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
    """主要なセキュリティヘッダーの設定状況を確認する。判定は rules 側。"""
    url = response.url
    observation = Observation.ok("http_headers", url, {
        "headers": {name: response.headers.get(name) for name in WATCHED_HEADERS},
        "duplicates": {},
        "status": getattr(response, "status_code", 200),
        "downgraded": _downgraded(response),
    })

    is_https = urlparse(url).scheme.lower() == "https"
    findings = []
    for finding in _run_rules(_HEADER_RULES, observation, _HEADER_SUBTYPES):
        if finding["subtype"] == "Strict-Transport-Security" and not is_https:
            continue
        header = finding["subtype"]
        finding["description"] = f"{header}ヘッダーが確認できませんでした。"
        findings.append(finding)
    return findings


_RULES = Path(__file__).resolve().parent.parent / "rules"
_HEADER_RULES = _RULES / "headers"
_COOKIE_RULES = _RULES / "cookies"

WATCHED_HEADERS = (
    "content-security-policy",
    "content-security-policy-report-only",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)

_HEADER_SUBTYPES = {
    "headers.csp-missing": ("SECURITY_HEADER", "Content-Security-Policy", "CSPが設定されていません"),
    "headers.hsts-missing": ("SECURITY_HEADER", "Strict-Transport-Security", "HSTSが設定されていません"),
    "headers.referrer-policy-missing": ("SECURITY_HEADER", "Referrer-Policy", "Referrer-Policyが設定されていません"),
    "headers.x-content-type-options-missing": ("SECURITY_HEADER", "X-Content-Type-Options", "X-Content-Type-Optionsが設定されていません"),
    "headers.x-frame-options-missing": ("SECURITY_HEADER", "X-Frame-Options", "X-Frame-Optionsが設定されていません"),
}
_COOKIE_SUBTYPES = {
    "cookies.httponly-missing": ("COOKIE", "COOKIE_HTTPONLY_MISSING", "HttpOnly属性が設定されていません"),
    "cookies.over-http": ("COOKIE", "COOKIE_SECURE_MISSING", "Secure属性が設定されていません"),
    "cookies.samesite-invalid": ("COOKIE", "COOKIE_SAMESITE_INVALID", "SameSite属性の値が不正です"),
    "cookies.samesite-missing": ("COOKIE", "COOKIE_SAMESITE_MISSING", "SameSite属性が設定されていません"),
    "cookies.samesite-none": ("COOKIE", "COOKIE_SAMESITE_NONE_WITHOUT_SECURE", "SameSite=NoneのCookieにSecureが設定されていません"),
    "cookies.secure-missing": ("COOKIE", "COOKIE_SECURE_MISSING", "Secure属性が設定されていません"),
}

_COOKIE_REASONS = {
    "COOKIE_HTTPONLY_MISSING": "HttpOnlyがないためJavaScriptからCookieを読める可能性があります。",
    "COOKIE_SECURE_MISSING": "HTTPSレスポンスで発行されたCookieにSecureがありません。",
    "COOKIE_SAMESITE_MISSING": "SameSiteが明示されていません。ブラウザーの既定動作は環境により異なる場合があります。",
    "COOKIE_SAMESITE_INVALID": "SameSiteの値がStrict、Lax、Noneのいずれでもありません。",
    "COOKIE_SAMESITE_NONE_WITHOUT_SECURE": "SameSite=NoneにはSecureの併用が必要です。",
}

_REDIRECT_RULES = _RULES / "redirects"

_REDIRECT_SUBTYPES = {
    "redirects.http-external": ("REDIRECT", "HTTP_REDIRECT", "外部ドメインへのHTTPリダイレクトが検出されました"),
    "redirects.http-internal": ("REDIRECT", "HTTP_REDIRECT", "HTTPリダイレクトが検出されました"),
    "redirects.meta-refresh-external": ("REDIRECT", "META_REFRESH", "外部ドメインへのMeta Refreshが検出されました"),
    "redirects.meta-refresh-internal": ("REDIRECT", "META_REFRESH", "Meta Refreshが検出されました"),
    "redirects.js-redirect-external": ("REDIRECT", "JS_REDIRECT", "外部ドメインへのJavaScriptリダイレクトが検出されました"),
    "redirects.js-redirect-internal": ("REDIRECT", "JS_REDIRECT", "JavaScriptリダイレクトが検出されました"),
}


def _external(url, destination_url) -> bool:
    return urlparse(url).netloc.lower() != urlparse(destination_url).netloc.lower()



def _run_rules(rules_dir, observation, subtypes):
    """ルールを当て、旧 Finding 形式に写す。"""
    index = rule_runner.ObservationIndex()
    index.add(observation)
    normal, low = rule_runner.run(
        load_rules_from_dir(rules_dir),
        [observation],
        satisfied=frozenset({"proof", "consent"}),
    )

    findings = []
    for found in normal + low:
        mapped = subtypes.get(found.rule_id)
        if mapped is None:
            continue
        kind, subtype, title = mapped
        findings.append({
            "type": kind,
            "subtype": subtype,
            "severity": found.severity,
            "title": title,
            "url": observation.subject,
            "description": found.message,
            "recommendation": found.fix,
        })
    return findings

def _downgraded(response):
    """https から http へ落ちた遷移があるか。"""
    previous = "https" if urlparse(response.url).scheme.lower() == "https" else "http"
    for step in reversed(getattr(response, "history", []) or []):
        scheme = urlparse(getattr(step, "url", "")).scheme.lower()
        if scheme == "https" and previous == "http":
            return True
        previous = scheme
    return False



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

    observation = Observation.ok("http_redirects", response.url, {
        "chain": redirect_chain,
        "chain_length": len(redirect_chain),
        "external": external_redirect,
        "final_url": response.url,
    })

    evidence = "\n".join(
        f'{item["status"]}: {item["from"]} -> {item["to"]}' for item in redirect_chain
    ) + f"\nFinal URL: {response.url}"

    for finding in _run_rules(_REDIRECT_RULES, observation, _REDIRECT_SUBTYPES):
        if finding["subtype"] != "HTTP_REDIRECT":
            continue
        finding["url"] = redirect_chain[0]["from"]
        finding["evidence"] = evidence
        findings.append(finding)

    return findings


def check_meta_refresh(url, response):
    """HTMLのMeta Refreshによる自動遷移を検出する。判定は rules 側。"""
    for meta_tag in re.findall(r"<meta\b[^>]*>", response.text, re.IGNORECASE):
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

        content = next((v for v in content_match.groups() if v is not None), "")
        url_match = re.search(r"(?:^|;)\s*url\s*=\s*(.+?)\s*$", content, re.IGNORECASE)
        if not url_match:
            continue

        destination = url_match.group(1).strip().strip("'\"")
        if not destination:
            continue

        destination_url = urljoin(response.url, destination)
        observation = Observation.ok("http_redirects", response.url, {
            "chain": [],
            "chain_length": 0,
            "external": False,
            "final_url": response.url,
            "meta_refresh": {
                "destination": destination_url,
                "content": content,
                "external": _external(response.url, destination_url),
            },
        })

        findings = []
        for finding in _run_rules(_REDIRECT_RULES, observation, _REDIRECT_SUBTYPES):
            if finding["subtype"] != "META_REFRESH":
                continue
            finding["evidence"] = (
                f"Meta Refresh: {response.url} -> {destination_url}\nContent: {content}"
            )
            findings.append(finding)
        return findings

    return []

def check_js_redirect(url, response):
    """HTML内のJavaScriptによるリダイレクトを検出する。判定は rules 側。"""
    script_blocks = re.findall(
        r"<script\b[^>]*>(.*?)</script>", response.text, re.IGNORECASE | re.DOTALL
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
            observation = Observation.ok("http_redirects", response.url, {
                "chain": [],
                "chain_length": 0,
                "external": False,
                "final_url": response.url,
                "js_redirect": {
                    "destination": destination_url,
                    "script": script.strip(),
                    "external": _external(response.url, destination_url),
                },
            })

            findings = []
            for finding in _run_rules(_REDIRECT_RULES, observation, _REDIRECT_SUBTYPES):
                if finding["subtype"] != "JS_REDIRECT":
                    continue
                finding["evidence"] = (
                    f"JavaScript Redirect: {response.url} -> {destination_url}\n"
                    f"Script: {script.strip()}"
                )
                findings.append(finding)
            return findings

    return []

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
    """Set-Cookie 属性を確認する。判定は rules 側、Evidence は Cookie 単位。"""
    cookie_headers = _get_set_cookie_headers(response)
    if not cookie_headers:
        return []

    is_https = urlparse(response.url).scheme.lower() == "https"
    issues = []

    for index, header in enumerate(cookie_headers, start=1):
        cookie = _parse_cookie(header, f"Cookie #{index}")
        if cookie is None:
            continue

        samesite = (cookie["same_site"] or "").lower() or None
        observation = Observation.ok("http_cookies", response.url, {
            "cookies": [{
                "id": cookie["reference"],
                "attributes": {
                    "httponly": cookie["httponly"],
                    "secure": cookie["secure"],
                },
                "samesite": samesite,
                "samesite_valid": cookie["same_site_valid"],
            }],
            "count": 1,
            "secure_transport": is_https,
        })

        none_without_secure = samesite == "none" and not cookie["secure"]
        severity = "MEDIUM" if cookie["sensitive_candidate"] else "LOW"

        for finding in _run_rules(_COOKIE_RULES, observation, _COOKIE_SUBTYPES):
            subtype = finding["subtype"]
            if none_without_secure and subtype == "COOKIE_SECURE_MISSING":
                continue
            if subtype == "COOKIE_SECURE_MISSING" and not is_https:
                continue
            if subtype == "COOKIE_SAMESITE_NONE_WITHOUT_SECURE" and cookie["secure"]:
                continue        

            reason = _COOKIE_REASONS[subtype]
            finding["severity"] = severity
            finding["description"] = (
                f"{reason} {cookie['purpose']}。{cookie['confidence']}。"
                " 用途はCookie名からの推定であり、実際の用途は未確認です。"
            )
            finding["evidence"] = _cookie_attribute_evidence(cookie)
            issues.append(finding)

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
