"""Same-origin HTML crawler with stable, conservative URL identity."""

import re
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup


_META_CHARSET = re.compile(
    br"<meta\b[^>]*(?:charset\s*=\s*[\"']?\s*([\w.-]+)|"
    br"content\s*=\s*[\"'][^\"']*charset\s*=\s*([\w.-]+))",
    re.IGNORECASE,
)


def _decode_html(response):
    """Decode response bytes once: HTTP charset, HTML meta, then UTF-8."""
    content = response.content
    content_type = response.headers.get("Content-Type", "")
    match = re.search(r"charset\s*=\s*[\"']?\s*([^;\s\"']+)", content_type, re.I)
    charset = match.group(1) if match else None
    if not charset:
        meta = _META_CHARSET.search(content[:8192])
        if meta:
            charset = meta.group(1) or meta.group(2)
            if isinstance(charset, bytes):
                charset = charset.decode("ascii", errors="ignore")
    if charset:
        try:
            return content.decode(charset)
        except (LookupError, UnicodeDecodeError):
            # An invalid declared charset/content must not abort the crawl.
            pass
    return content.decode("utf-8", errors="replace")


def normalize_url(url):
    """Normalize URL spelling without dropping meaningful query data."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname.lower()
        # Keep explicit ports: scope checks distinguish ports, and URL identity
        # remains conservative about authored URL forms.
        netloc = host
        if ":" in host:  # IPv6 literal
            netloc = f"[{host}]"
        if parts.port is not None:
            netloc += f":{parts.port}"
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~%")
        query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~%")
        # Escape hex casing is immaterial; uppercase it without decoding any
        # escaped bytes, which avoids mojibake repair and double encoding.
        path = re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), path)
        query = re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), query)
        return urlunsplit((scheme, netloc, path, query, ""))
    except (TypeError, ValueError, UnicodeError):
        return None


def crawl(start_url, max_pages=100):
    """Explore at most max_pages URLs on the starting origin."""
    start_url = normalize_url(start_url)
    if not start_url:
        raise ValueError("開始URLが不正です")
    start_parsed = urlsplit(start_url)
    target_host = start_parsed.hostname
    target_port = start_parsed.port or (443 if start_parsed.scheme == "https" else 80)
    target_scheme = start_parsed.scheme

    def in_scope(url):
        normalized = normalize_url(url)
        if not normalized:
            return False
        parsed = urlsplit(normalized)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return (parsed.hostname == target_host and port == target_port
                and parsed.scheme == target_scheme)

    queue = [start_url]
    queued = {start_url}
    visited = set()
    while queue and len(visited) < max_pages:
        current = queue.pop(0)
        if current in visited:
            continue
        try:
            response = requests.get(current, timeout=5, allow_redirects=False)
            if 300 <= response.status_code < 400:
                continue
            response.raise_for_status()
        except (requests.RequestException, ValueError) as exc:
            print(f"アクセス失敗: {current}\n理由: {exc}")
            continue
        visited.add(current)
        if "html" not in response.headers.get("Content-Type", "text/html").lower():
            continue
        soup = BeautifulSoup(_decode_html(response), "html.parser")
        for link in soup.find_all("a", href=True):
            try:
                candidate = normalize_url(urljoin(current, link["href"]))
            except (TypeError, ValueError, UnicodeError):
                continue
            if candidate and in_scope(candidate) and candidate not in queued:
                queue.append(candidate)
                queued.add(candidate)
    return visited


if __name__ == "__main__":
    print("\n".join(sorted(crawl("http://localhost:5000", max_pages=10))))
