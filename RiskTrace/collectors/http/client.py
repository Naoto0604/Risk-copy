"""Scheduler 配下でしか動かない HTTP クライアント。

Collector は requests を直接呼ばず、必ずこれを通す。

方針:
    - 通信の前に予算確保・スコープ検証・中断確認・時間確認を行う
    - リダイレクトは手動追跡。1 ホップごとに同じ検証を通す
    - リダイレクトは REDIRECT 予算を、再試行は RETRY 予算を消費する
    - スコープ外へ出たら追跡を打ち切る（ScopeViolation）
    - https から http への遷移を downgraded に記録する。判定はしない
    - 本文は上限で切る

transport は差し替え可能。テストはネットワーク無しで回せる。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urljoin, urlsplit

import requests

from engine.scheduler import REDIRECT, REQUEST, RETRY, Scheduler, ScopeViolation

MAX_HOPS = 5
MAX_BODY_BYTES = 256 * 1024
MAX_RETRIES = 1

Transport = Callable[[str, str, tuple[float, float]], tuple[int, Iterable[tuple[str, str]], bytes]]


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: str
    redirects: tuple[str, ...]
    downgraded: bool

    def all(self, name: str) -> list[str]:
        """同名ヘッダーの値をすべて返す。"""
        target = name.lower()
        return [value for key, value in self.headers if key.lower() == target]

    def first(self, name: str) -> str | None:
        values = self.all(name)
        return values[0] if values else None

    @property
    def content_type(self) -> str:
        return self.first("content-type") or ""


class FetchError(Exception):
    """取得に失敗した。"""


def _decode(body: bytes, content_type: str) -> str:
    charset = None
    for chunk in content_type.split(";"):
        chunk = chunk.strip()
        if chunk.lower().startswith("charset="):
            charset = chunk.split("=", 1)[1].strip().strip('"')
    if charset:
        try:
            return body[:MAX_BODY_BYTES].decode(charset, errors="replace")
        except LookupError:
            pass
    return body[:MAX_BODY_BYTES].decode("utf-8", errors="replace")


def _first_header(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return None


def requests_transport(url: str, method: str, timeout: tuple[float, float]):
    """既定の transport。リダイレクトは追わない。"""
    response = requests.request(
        method,
        url,
        timeout=timeout,
        allow_redirects=False,
    )
    if response.raw is not None:
        headers = tuple(response.raw.headers.items())
    else:
        headers = tuple(response.headers.items())
    return response.status_code, headers, response.content


def fetch(
    url: str,
    scheduler: Scheduler,
    *,
    method: str = "GET",
    transport: Transport | None = None,
) -> HttpResponse:
    """1 リソースを取得する。リダイレクトは予算とスコープの範囲で追う。"""
    send = transport or requests_transport
    current = url
    history: list[str] = []
    downgraded = False
    attempts = 0

    while True:
        scheduler.check_cancel()
        scheduler.check_time()
        scheduler.check_scope(current)

        host = urlsplit(current).hostname or ""
        scheduler.reserve(REQUEST)

        try:
            with scheduler.slot(host):
                status, headers, body = send(current, method, scheduler.http_timeout())
        except requests.RequestException as exc:
            if attempts < MAX_RETRIES and scheduler.try_reserve(RETRY):
                attempts += 1
                scheduler.record("retry", url=current, error=type(exc).__name__)
                continue
            raise FetchError(f"{type(exc).__name__}: {exc}") from exc

        header_tuple = tuple((str(k), str(v)) for k, v in headers)
        location = _first_header(header_tuple, "location")

        # 3xx かつ Location があり、ホップ上限に達していなければ追跡する。
        # 追わない場合も下の return を通すため break は使わない。
        if 300 <= status < 400 and location and len(history) < MAX_HOPS:
            scheduler.reserve(REDIRECT)
            target = urljoin(current, location)
            if urlsplit(current).scheme == "https" and urlsplit(target).scheme == "http":
                downgraded = True
            scheduler.check_scope(target)
            history.append(current)
            current = target
            continue

        return HttpResponse(
            url=current,
            status=status,
            headers=header_tuple,
            body=_decode(bytes(body), _first_header(header_tuple, "content-type") or ""),
            redirects=tuple(history),
            downgraded=downgraded,
        )