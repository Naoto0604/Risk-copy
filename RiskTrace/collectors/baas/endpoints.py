"""BaaS（Supabase / Firebase）の公開エンドポイント観測。

観測のみ。severity も confidence も決めない。
参照を見つけ、既知のエンドポイントを 1 回だけ叩いて、返った形を残す。
認証はしない。鍵の有効性も判定しない。

方針:
    - 本文とアセット URL から project ref / project id を拾う
    - 叩くのは既知エンドポイントだけ。列挙はしない
    - 外部ホストなのでスコープ検証はしない（dns Collector と同じ扱い）
    - 返った JSON の形だけを見る。中身の評価はルール側
    - 中断（Cancelled）は伝播させる。予算・時間切れは打ち切り扱い
"""

from __future__ import annotations

import json
import re
from typing import Callable, Iterable
from urllib.parse import urlsplit

from engine.observations import Observation
from engine.scheduler import BudgetExhausted, Cancelled, TimeBudgetExhausted

COLLECTOR = "baas_endpoints"

MAX_REFS = 3
MAX_PROBES = 6
SNIPPET_LENGTH = 120

SUPABASE = "supabase"
FIREBASE = "firebase"

#: project ref / project id の抽出。誤検出は後段の疎通で落ちる。
SUPABASE_PATTERN = re.compile(r"https://([a-z0-9]{10,32})\.supabase\.co", re.IGNORECASE)
FIREBASE_PATTERNS = (
    re.compile(r"https://([a-z0-9-]{3,40})\.firebaseio\.com", re.IGNORECASE),
    re.compile(r"https://([a-z0-9-]{3,40})\.firebaseapp\.com", re.IGNORECASE),
    re.compile(r"https://([a-z0-9-]{3,40})\.web\.app", re.IGNORECASE),
)

TEXT_TYPES = ("application/json", "text/plain", "text/html")

Fetch = Callable[[str], tuple[int, str]]


def extract_refs(text: str) -> list[tuple[str, str]]:
    """(kind, ref) を出現順に返す。重複は落とす。"""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for match in SUPABASE_PATTERN.finditer(text or ""):
        item = (SUPABASE, match.group(1).lower())
        if item not in seen:
            seen.add(item)
            found.append(item)

    for pattern in FIREBASE_PATTERNS:
        for match in pattern.finditer(text or ""):
            item = (FIREBASE, match.group(1).lower())
            if item not in seen:
                seen.add(item)
                found.append(item)

    return found


def _endpoints(kind: str, ref: str) -> list[str]:
    if kind == SUPABASE:
        return [f"https://{ref}.supabase.co/rest/v1/"]
    return [
        f"https://{ref}.firebaseio.com/.json?shallow=true",
        f"https://{ref}.firebaseapp.com/__/firebase/init.json",
    ]


def _snippet(response_text: str, content_type: str) -> str | None:
    if not content_type.lower().startswith(TEXT_TYPES):
        return None
    text = response_text.strip()
    return text[:SNIPPET_LENGTH] or None


def _json_flags(body: str) -> dict:
    """JSON の形だけを見る。値は評価しない。"""
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        return {"json": False, "openapi": False, "has_api_key": False, "auth_domain": None}

    if not isinstance(document, dict):
        return {"json": True, "openapi": False, "has_api_key": False, "auth_domain": None}

    return {
        "json": True,
        "openapi": "openapi" in document or "paths" in document,
        "has_api_key": bool(document.get("apiKey")),
        "auth_domain": document.get("authDomain") if isinstance(document.get("authDomain"), str) else None,
    }


def collect(
    documents: Iterable[tuple[str, str]],
    scheduler,
    *,
    asset_urls: Iterable[str] = (),
    fetch: Fetch | None = None,
) -> Observation:
    """参照を集め、既知エンドポイントを叩く。"""
    docs = [(str(url), str(body)) for url, body in (documents or ())]
    subject = docs[0][0] if docs else "-"

    text = "\n".join(body for _url, body in docs)
    text += "\n" + "\n".join(str(url) for url in (asset_urls or ()))

    refs = extract_refs(text)[:MAX_REFS]
    if not refs:
        return Observation.ok(
            COLLECTOR,
            subject,
            {"refs": [], "probes": [], "found": [], "counts": {},
             "truncated": False, "truncated_reason": None},
            note="BaaS の参照が見つかりませんでした",
        )

    if fetch is None:
        from collectors.http.client import requests_transport

        def fetch(url: str) -> tuple[int, str]:
            status, _headers, body = requests_transport(url, "GET", scheduler.http_timeout())
            return status, body.decode("utf-8", errors="replace")

    probes: list[dict] = []
    truncated: str | None = None

    for kind, ref in refs:
        for url in _endpoints(kind, ref):
            if len(probes) >= MAX_PROBES:
                truncated = "probes"
                break

            host = urlsplit(url).hostname or ""
            try:
                scheduler.check_cancel()
                scheduler.check_time()
                scheduler.reserve("request")
                with scheduler.slot(host):
                    status, body = fetch(url)
            except (BudgetExhausted, TimeBudgetExhausted):
                truncated = "budget"
                break
            except Cancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - 1 件の失敗で全体を落とさない
                probes.append({"kind": kind, "ref": ref, "url": url, "status": None,
                               "reachable": False, "content_type": None, "snippet": None,
                               "json": False, "openapi": False, "has_api_key": False,
                               "auth_domain": None, "error": f"{type(exc).__name__}: {exc}"})
                continue

            content_type = ""
            flags = _json_flags(body)
            probes.append({
                "kind": kind,
                "ref": ref,
                "url": url,
                "status": status,
                "reachable": 200 <= status < 500,
                "content_type": content_type,
                "snippet": _snippet(body, "application/json"),
                "error": None,
                **flags,
            })
        if truncated == "budget":
            break

    reachable = [probe["url"] for probe in probes if probe["reachable"]]
    note = "予算または時間の上限に達したため打ち切り" if truncated else None

    return Observation.ok(
        COLLECTOR,
        subject,
        {
            "refs": [{"kind": kind, "ref": ref} for kind, ref in refs],
            "probes": probes,
            "found": reachable,
            "counts": {
                "supabase": sum(1 for kind, _ref in refs if kind == SUPABASE),
                "firebase": sum(1 for kind, _ref in refs if kind == FIREBASE),
                "reachable": len(reachable),
            },
            "truncated": truncated is not None,
            "truncated_reason": truncated,
        },
        note=note,
    )