"""URL の scheme を観測する Collector。

通信しない。HTTPS 判定の材料を Observation に置くだけ。
"""

from __future__ import annotations

from urllib.parse import urlsplit

from engine.observations import Observation

COLLECTOR = "http_transport"


def collect(target: str, scheduler=None) -> Observation:
    scheme = (urlsplit(target).scheme or "").lower()
    if scheme not in {"http", "https"}:
        return Observation.error(COLLECTOR, target or "-", "scheme が http/https ではありません")
    return Observation.ok(COLLECTOR, target, {"scheme": scheme})