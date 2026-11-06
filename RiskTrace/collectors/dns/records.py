"""DNS レコードの Collector（SPF / DMARC / DKIM）。

観測のみ。ポリシーの妥当性は判定しない。

方針:
    - DNS over HTTPS を使う。通常の HTTPS GET なので Scheduler 配下に乗る
    - SPF は多重定義かどうかを数える（レコード数は観測事実）
    - DMARC は存在と p= の値だけを見る
    - DKIM は selector が不明なら「確認できなかった」を明示する。
      見つからなくても存在しないと断定しない
"""

from __future__ import annotations

import json
from typing import Callable

from engine.observations import Observation

COLLECTOR = "dns"

DOH_ENDPOINT = "https://dns.google/resolve"
MAX_RESPONSE_CHARS = 16384

TXT = 16

#: DKIM の探索に使う既知 selector。網羅はしない。
COMMON_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "mail",
    "dkim",
)

FetchResult = Callable[[str], tuple[int, str]]


class DnsError(Exception):
    """DNS 照会に失敗した。"""


def _query(name: str, record_type: str, fetch: FetchResult, scheduler) -> list[str]:
    """TXT を引いて値の一覧を返す。1 クエリ 1 リクエスト。"""
    scheduler.check_cancel()
    scheduler.check_time()
    url = f"{DOH_ENDPOINT}?name={name}&type={record_type}"
    scheduler.reserve("request")

    with scheduler.slot("dns.google"):
        status, payload = fetch(url)

    if status != 200:
        raise DnsError(f"DNS 照会が HTTP {status}")

    try:
        document = json.loads(payload[:MAX_RESPONSE_CHARS])
    except (TypeError, ValueError) as exc:
        raise DnsError("DNS 応答を解析できません") from exc

    if not isinstance(document, dict):
        raise DnsError("DNS 応答の形式が不正です")

    values: list[str] = []
    for answer in document.get("Answer") or []:
        if not isinstance(answer, dict) or answer.get("type") != TXT:
            continue
        data = answer.get("data")
        if isinstance(data, str):
            values.append(data.strip().strip('"'))
    return values


def _spf_policy(value: str) -> str | None:
    """``all`` の修飾子だけを取り出す。"""
    for token in value.split():
        lowered = token.lower()
        if lowered.endswith("all") and lowered[:-3] in ("+", "-", "~", "?"):
            return lowered
    return None


def collect(
    domain: str,
    scheduler,
    *,
    selectors: tuple[str, ...] = COMMON_SELECTORS,
    fetch: FetchResult | None = None,
) -> Observation:
    """SPF / DMARC / DKIM を観測する。"""
    if fetch is None:
        from collectors.http.client import requests_transport

        def fetch(url: str) -> tuple[int, str]:
            status, headers, body = requests_transport(url, "GET", scheduler.http_timeout())
            return status, body.decode("utf-8", errors="replace")

    data: dict = {"domain": domain}

    try:
        spf_records = [v for v in _query(domain, "TXT", fetch, scheduler)
                       if v.lower().startswith("v=spf1")]
        data["spf"] = {
            "present": bool(spf_records),
            "count": len(spf_records),
            "multiple": len(spf_records) > 1,
            "policy": _spf_policy(spf_records[0]) if spf_records else None,
        }

        dmarc_records = [v for v in _query(f"_dmarc.{domain}", "TXT", fetch, scheduler)
                         if v.lower().startswith("v=dmarc1")]
        data["dmarc"] = {
            "present": bool(dmarc_records),
            "policy": next(
                (token.split("=", 1)[1].strip().lower()
                 for token in (dmarc_records[0].split(";") if dmarc_records else [])
                 if token.strip().lower().startswith("p=")),
                None,
            ),
        }
    except DnsError as exc:
        return Observation.error(COLLECTOR, domain, str(exc))

    found: list[str] = []
    for selector in selectors:
        try:
            values = _query(f"{selector}._domainkey.{domain}", "TXT", fetch, scheduler)
        except DnsError:
            continue
        if any(value.lower().startswith("v=dkim1") or "p=" in value.lower() for value in values):
            found.append(selector)

    data["dkim"] = {
        "selectors_found": found,
        "selectors_tried": list(selectors),
        "resolved": bool(found),
    }

    return Observation.ok(COLLECTOR, domain, data)