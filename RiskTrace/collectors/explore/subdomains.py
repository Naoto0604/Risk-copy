"""サブドメインの名前解決だけを見る Collector。

観測のみ。severity も confidence も決めない。
「その名前が解決するか」だけを残す。

方針:
    - 全列挙はしない。よく使う名前の固定リストを引く
    - DNS は DoH（dns.google）経由。Scheduler 配下に乗る
    - 解決してもスコープ外として扱う。勝手にクロールはしない
    - NXDOMAIN と「応答はあるが A が無い」を区別する
    - 打ち切り理由は残す。中断（Cancelled）は伝播させる

apex は末尾 2 ラベルで推定する。co.uk のような多段 TLD は区別しない。
"""

from __future__ import annotations

import json
from typing import Callable

from engine.observations import Observation
from engine.scheduler import BudgetExhausted, Cancelled, TimeBudgetExhausted

COLLECTOR = "explore_subdomains"

DOH_ENDPOINT = "https://dns.google/resolve"
MAX_RESPONSE_CHARS = 16384

A = 1
NOERROR = 0
NXDOMAIN = 3

#: 試す名前。網羅はしない。
COMMON_NAMES: tuple[str, ...] = (
    "www",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "app",
    "mail",
    "cdn",
    "static",
    "docs",
    "vpn",
    "git",
)

MAX_NAMES = 20

FetchResult = Callable[[str], tuple[int, str]]


def _apex(host: str) -> str:
    """推定の親ドメイン。末尾 2 ラベル。"""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host
    return ".".join(labels[-2:])


def _host_of(target: str) -> str | None:
    from urllib.parse import urlsplit

    text = (target or "").strip()
    if not text:
        return None
    if "://" in text:
        try:
            return (urlsplit(text).hostname or "").lower() or None
        except ValueError:
            return None
    return text.split("/", 1)[0].lower() or None


def _lookup(fqdn: str, fetch: FetchResult, scheduler) -> tuple[str, list[str]]:
    """A レコードを引く。1 クエリ 1 リクエスト。"""
    scheduler.check_cancel()
    scheduler.check_time()
    scheduler.reserve("request")

    url = f"{DOH_ENDPOINT}?name={fqdn}&type=A"
    with scheduler.slot("dns.google"):
        status, payload = fetch(url)

    if status != 200:
        return "error", []

    try:
        document = json.loads(payload[:MAX_RESPONSE_CHARS])
    except (TypeError, ValueError):
        return "error", []

    if not isinstance(document, dict):
        return "error", []

    code = document.get("Status")
    if code == NXDOMAIN:
        return "nxdomain", []
    if code != NOERROR:
        return "error", []

    addresses: list[str] = []
    for answer in document.get("Answer") or []:
        if not isinstance(answer, dict) or answer.get("type") != A:
            continue
        data = answer.get("data")
        if isinstance(data, str) and data.strip():
            addresses.append(data.strip())

    return ("resolved" if addresses else "no_answer"), addresses


def collect(
    target: str,
    scheduler,
    *,
    names: tuple[str, ...] = COMMON_NAMES,
    fetch: FetchResult | None = None,
) -> Observation:
    """親ドメイン配下のよく使う名前を引き、解決結果を返す。"""
    host = _host_of(target)
    if not host:
        return Observation.error(COLLECTOR, target or "-", "ホスト名を取得できません")

    if fetch is None:
        from collectors.http.client import requests_transport

        def fetch(url: str) -> tuple[int, str]:
            status, _headers, body = requests_transport(url, "GET", scheduler.http_timeout())
            return status, body.decode("utf-8", errors="replace")

    apex = _apex(host)
    candidates = [name for name in tuple(names)[:MAX_NAMES] if name.strip()]

    results: list[dict] = []
    truncated: str | None = None

    for name in candidates:
        fqdn = f"{name}.{apex}"
        try:
            state, addresses = _lookup(fqdn, fetch, scheduler)
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
            break
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001 - 1 件の失敗で全体を落とさない
            results.append({"name": name, "fqdn": fqdn, "state": "error",
                            "addresses": [], "error": f"{type(exc).__name__}: {exc}"})
            continue

        results.append({"name": name, "fqdn": fqdn, "state": state,
                        "addresses": addresses, "error": None})

    resolved = [entry["fqdn"] for entry in results if entry["state"] == "resolved"]

    note = "予算または時間の上限に達したため打ち切り" if truncated else None

    return Observation.ok(
        COLLECTOR,
        host,
        {
            "host": host,
            "apex": apex,
            "names": results,
            "resolved": resolved,
            "resolved_count": len(resolved),
            "counts": {
                state: sum(1 for entry in results if entry["state"] == state)
                for state in ("resolved", "no_answer", "nxdomain", "error")
            },
            "truncated": truncated is not None,
            "truncated_reason": truncated,
            "in_scope": False,
        },
        note=note,
    )