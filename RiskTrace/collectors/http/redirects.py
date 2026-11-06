"""HTTP / Meta Refresh / JavaScript リダイレクトの Collector。

観測のみ。severity も confidence も決めない。判定は YAML ルール側。

方針:
    - リダイレクト経路は client が辿った history をそのまま残す
    - Meta Refresh と JavaScript は本文から1件だけ拾う
    - 外部ホストかどうかだけを判定材料として添える
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from collectors.http import client
from engine.observations import Observation

COLLECTOR = "http_redirects"

META_TAG = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
META_REFRESH = re.compile(
    r"""\bhttp-equiv\s*=\s*(?:"refresh"|'refresh'|refresh)(?=\s|/?>)""", re.IGNORECASE
)
META_CONTENT = re.compile(
    r"""\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE
)
META_URL = re.compile(r"(?:^|;)\s*url\s*=\s*(.+?)\s*$", re.IGNORECASE)

SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
SCRIPT_PATTERNS = (
    re.compile(r"""(?:window\.)?location\.href\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""(?:window\.)?location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)""", re.IGNORECASE),
    re.compile(r"""(?:window\.)?location\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE),
)


def _external(base: str, destination: str) -> bool:
    return (urlsplit(base).netloc or "").lower() != (urlsplit(destination).netloc or "").lower()


def meta_refresh(url: str, body: str) -> dict | None:
    """Meta Refresh を1件だけ返す。"""
    for tag in META_TAG.findall(body or ""):
        if not META_REFRESH.search(tag):
            continue

        content_match = META_CONTENT.search(tag)
        if not content_match:
            continue

        content = next((v for v in content_match.groups() if v is not None), "")
        url_match = META_URL.search(content)
        if not url_match:
            continue

        destination = url_match.group(1).strip().strip("'\"")
        if not destination:
            continue

        target = urljoin(url, destination)
        return {
            "destination": target,
            "content": content,
            "external": _external(url, target),
        }
    return None


def js_redirect(url: str, body: str) -> dict | None:
    """JavaScript による遷移を1件だけ返す。"""
    for script in SCRIPT_BLOCK.findall(body or ""):
        for pattern in SCRIPT_PATTERNS:
            match = pattern.search(script)
            if not match:
                continue
            target = urljoin(url, match.group(1).strip())
            return {
                "destination": target,
                "script": script.strip(),
                "external": _external(url, target),
            }
    return None


def collect(
    url: str,
    scheduler,
    *,
    transport: client.Transport | None = None,
) -> Observation:
    """リダイレクト経路と自動遷移を観測する。"""
    try:
        response = client.fetch(url, scheduler, transport=transport)
    except client.FetchError as exc:
        return Observation.error(COLLECTOR, url, str(exc))
    except Exception as exc:  # noqa: BLE001
        return Observation.error(COLLECTOR, url, f"{type(exc).__name__}: {exc}")

    chain = [
        {"status": None, "from": url, "to": hop} for hop in response.redirects
    ]
    if chain:
        chain[-1]["to"] = response.url

    return Observation.ok(
        COLLECTOR,
        response.url,
        {
            "chain": chain,
            "chain_length": len(chain),
            "external": any(_external(item["from"], item["to"]) for item in chain),
            "final_url": response.url,
            "meta_refresh": meta_refresh(response.url, response.body),
            "js_redirect": js_redirect(response.url, response.body),
        },
    )