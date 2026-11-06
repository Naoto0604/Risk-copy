"""Set-Cookie 属性の Collector。

観測のみ。値も名前も保存せず、`Cookie #N` の識別子だけを残す。

方針:
    - 属性名は完全一致で判定する（xhttponly を HttpOnly と誤認しない）
    - SameSite の値だけは記録する（組み合わせの判断材料になる）
    - Expires のカンマで分割しない
    - 属性の有無を返すだけで、severity は決めない
"""

from __future__ import annotations

import re

from collectors.http import client
from engine.observations import Observation

COLLECTOR = "http_cookies"

#: 記録する属性。小文字で保持する。
TRACKED_ATTRIBUTES: tuple[str, ...] = (
    "secure",
    "httponly",
    "samesite",
    "domain",
    "path",
    "max-age",
    "expires",
    "partitioned",
)

_VALID_SAMESITE = frozenset({"lax", "strict", "none"})

#: 属性名の直後が「=」か「;」か終端であることを要求する。
_ATTRIBUTE_PATTERNS = {
    name: re.compile(rf"(?:^|;)\s*{re.escape(name)}\s*(?:=|;|$)", re.IGNORECASE)
    for name in TRACKED_ATTRIBUTES
}

_SAMESITE_VALUE = re.compile(r"(?:^|;)\s*samesite\s*=\s*([^;\s]*)", re.IGNORECASE)


def split_set_cookie(values: list[str]) -> list[str]:
    """Set-Cookie ヘッダーを Cookie 単位に分ける。

    ``Expires=Wed, 21 Oct 2030 07:28:00 GMT`` のカンマで切らないよう、
    ``Expires=`` の直後のカンマだけを保護してから分割する。
    """
    parts: list[str] = []
    for value in values:
        buffer = []
        index = 0
        text = value
        while index < len(text):
            char = text[index]
            if char == ",":
                tail = text[index + 1:]
                stripped = tail.lstrip()
                is_date_continuation = bool(re.match(r"\d{1,2}\s+[A-Za-z]{3}\s+\d{4}", stripped))
                if not is_date_continuation:
                    parts.append("".join(buffer))
                    buffer = []
                    index += 1
                    continue
            buffer.append(char)
            index += 1
        if buffer:
            parts.append("".join(buffer))
    return [part.strip() for part in parts if part.strip()]


def _attributes(cookie: str) -> dict[str, bool]:
    return {
        name: bool(_ATTRIBUTE_PATTERNS[name].search(cookie))
        for name in TRACKED_ATTRIBUTES
    }


def _samesite(cookie: str) -> str | None:
    match = _SAMESITE_VALUE.search(cookie)
    if not match:
        return None
    value = match.group(1).strip().strip('"').lower()
    return value or None


def _is_valid_samesite(value: str | None) -> bool | None:
    if value is None:
        return None
    return value in _VALID_SAMESITE


def collect(
    url: str,
    scheduler,
    *,
    transport: client.Transport | None = None,
) -> Observation:
    """Set-Cookie 属性を観測する。"""
    try:
        response = client.fetch(url, scheduler, transport=transport)
    except client.FetchError as exc:
        return Observation.error(COLLECTOR, url, str(exc))
    except Exception as exc:  # noqa: BLE001
        return Observation.error(COLLECTOR, url, f"{type(exc).__name__}: {exc}")

    cookies = []
    for index, raw in enumerate(split_set_cookie(response.all("set-cookie")), start=1):
        attributes = _attributes(raw)
        samesite = _samesite(raw)
        cookies.append({
            "id": f"Cookie #{index}",
            "attributes": attributes,
            "samesite": samesite,
            "samesite_valid": _is_valid_samesite(samesite),
        })

    return Observation.ok(
        COLLECTOR,
        response.url,
        {
            "cookies": cookies,
            "count": len(cookies),
            "secure_transport": response.url.startswith("https://"),
            "downgraded": response.downgraded,
        },
    )