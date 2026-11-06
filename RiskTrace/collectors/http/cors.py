"""CORS 応答ヘッダーの観測。

観測のみ。severity も confidence も決めない。
どの Origin を送り、何が返ってきたかだけを残す。

方針:
    - 送信元を偽装した Origin 付き GET と、OPTIONS プリフライトの 2 回だけ
    - 返った ACAO が送った Origin と一致するか（反射）を真偽で残す
    - ``*``、``null``、資格情報許可、Vary の有無も残す
    - リダイレクトは追わない。CORS ヘッダーは応答ごとに決まるため
    - 予算・レート・スコープ・中断はすべて Scheduler 経由

`client.fetch` は追加ヘッダーを渡せないので、ここでは自前で送る。
"""

from __future__ import annotations

from typing import Callable, Iterable
from urllib.parse import urlsplit

import requests

from engine.observations import Observation
from engine.scheduler import BudgetExhausted, Cancelled, TimeBudgetExhausted

COLLECTOR = "http_cors"

#: 送る Origin。実在しないドメインなので、反射の判定に使える。
PROBE_ORIGIN = "https://risktrace-probe.invalid"

MAX_ORIGINS = 5

Request = Callable[[str, str, tuple[float, float], dict[str, str]],
                   tuple[int, Iterable[tuple[str, str]], bytes]]


def _requests_send(url: str, method: str, timeout: tuple[float, float],
                   headers: dict[str, str]):
    response = requests.request(
        method,
        url,
        timeout=timeout,
        headers=headers,
        allow_redirects=False,
    )
    raw = response.raw.headers.items() if response.raw is not None else response.headers.items()
    return response.status_code, tuple(raw), response.content


def _header(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return None


def _origins(value: str | None) -> list[str]:
    """ACAO を Origin 単位に割る。"""
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()][:MAX_ORIGINS]


def _send(url: str, method: str, scheduler, send: Request, headers: dict[str, str]) -> dict:
    """1 回送って、CORS に関する部分だけ抜き出す。"""
    scheduler.check_cancel()
    scheduler.check_time()
    scheduler.check_scope(url)
    scheduler.reserve("request")

    host = urlsplit(url).hostname or ""
    with scheduler.slot(host):
        status, response_headers, _body = send(url, method, scheduler.http_timeout(), headers)

    response_headers = list(response_headers)
    allow_origin = _header(response_headers, "access-control-allow-origin")
    vary = _header(response_headers, "vary")

    return {
        "method": method,
        "status": status,
        "allow_origin": allow_origin,
        "allow_origin_list": _origins(allow_origin),
        "reflected": allow_origin is not None and allow_origin.strip() == headers["Origin"],
        "wildcard": allow_origin is not None and allow_origin.strip() == "*",
        "null": allow_origin is not None and allow_origin.strip().lower() == "null",
        "credentials": (_header(response_headers, "access-control-allow-credentials") or "")
        .strip().lower() == "true",
        "allow_methods": _header(response_headers, "access-control-allow-methods"),
        "allow_headers": _header(response_headers, "access-control-allow-headers"),
        "vary_has_origin": bool(vary) and "origin" in vary.lower(),
        "location": _header(response_headers, "location"),
    }


def collect(
    url: str,
    scheduler,
    *,
    origin: str = PROBE_ORIGIN,
    send: Request | None = None,
    preflight: bool = True,
) -> Observation:
    """CORS 応答を観測する。"""
    sender = send or _requests_send
    probes: list[dict] = []
    truncated: str | None = None

    try:
        probes.append(_send(url, "GET", scheduler, sender, {"Origin": origin}))
    except (BudgetExhausted, TimeBudgetExhausted):
        truncated = "budget"
    except requests.RequestException as exc:
        return Observation.error(COLLECTOR, url, f"{type(exc).__name__}: {exc}")
    except Cancelled:
        raise
    except Exception as exc:  # noqa: BLE001
        return Observation.error(COLLECTOR, url, f"{type(exc).__name__}: {exc}")

    if preflight and truncated is None:
        try:
            probes.append(_send(
                url, "OPTIONS", scheduler, sender,
                {
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "content-type",
                },
            ))
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            probes.append({"method": "OPTIONS", "status": None, "error":
                           f"{type(exc).__name__}: {exc}"})

    note = "予算または時間の上限に達したため打ち切り" if truncated else None

    return Observation.ok(
        COLLECTOR,
        url,
        {
            "origin": origin,
            "probes": probes,
            "allow_origin": probes[0]["allow_origin"] if probes else None,
            "reflected": bool(probes and probes[0].get("reflected")),
            "wildcard": bool(probes and probes[0].get("wildcard")),
            "null": bool(probes and probes[0].get("null")),
            "credentials": bool(probes and probes[0].get("credentials")),
            "vary_has_origin": bool(probes and probes[0].get("vary_has_origin")),
            "preflight_supported": bool(
                len(probes) > 1 and probes[1].get("status") not in (None, 405, 501)
            ),
            "truncated": truncated is not None,
            "truncated_reason": truncated,
        },
        note=note,
    )