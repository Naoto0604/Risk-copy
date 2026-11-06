"""HTTP ヘッダー Collector。

観測のみ。severity も confidence も決めない。
値を評価せず、有無と重複だけを残す。判定は YAML ルール側で行う。
"""

from __future__ import annotations

from collections import Counter

from collectors.http import client
from engine.observations import Observation

COLLECTOR = "http_headers"

#: 観測対象のヘッダー。小文字で固定する。
WATCHED: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
    "access-control-allow-origin",
    "access-control-allow-credentials",
)


def _duplicates(headers: tuple[tuple[str, str], ...]) -> dict[str, int]:
    """2回以上現れたヘッダー名と件数。監視対象外も含める。"""
    counts = Counter(name.lower() for name, _value in headers)
    return {name: count for name, count in counts.items() if count > 1}


def collect(
    url: str,
    scheduler,
    *,
    transport: client.Transport | None = None,
) -> Observation:
    """ヘッダーを観測する。取得できなければ status=error を返す。"""
    try:
        response = client.fetch(url, scheduler, transport=transport)
    except client.FetchError as exc:
        return Observation.error(COLLECTOR, url, str(exc))
    except Exception as exc:  # noqa: BLE001
        return Observation.error(COLLECTOR, url, f"{type(exc).__name__}: {exc}")

    return Observation.ok(
        COLLECTOR,
        response.url,
        {
            "headers": {name: response.first(name) for name in WATCHED},
            "duplicates": _duplicates(response.headers),
            "status": response.status,
            "content_type": response.content_type,
            "redirects": list(response.redirects),
            "downgraded": response.downgraded,
        },
    )