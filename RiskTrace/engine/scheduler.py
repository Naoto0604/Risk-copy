"""すべてのネットワーク通信を統制する Scheduler。

Collector は直接 requests / socket / dns を呼ばず、必ずここを通る。

統制する項目:
    - Request Budget（HTTP・DNS・TCP 共通。種別は使用量の内訳として記録）
    - Time Budget（Job 全体の制限時間）
    - Concurrency（同時実行数）
    - Per-host Rate（ホスト単位の最小間隔）
    - Redirect Budget / Retry Budget（再試行もリダイレクトも予算を食う）
    - Cancellation（中断要求）
    - Scope Check（通信先の許可判定）
    - 通信タイムアウトの上限

方針:
    - 予算は実際の通信前に確定する（``reserve`` / ``require``）
    - 予算切れは診断全体の失敗ではない。呼び出し側は skipped に写像する
    - 中断は通信境界で確認する
    - 予算の残量と使用内訳をログに残せる

Worker Lease は Job キュー側（database/queue.py）が持つ。ここでは扱わない。
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator

REQUEST = "request"
REDIRECT = "redirect"
RETRY = "retry"

KINDS: tuple[str, ...] = (REQUEST, REDIRECT, RETRY)

#: 予算種別 → Budgets の属性名。``retry`` の複数形は不規則なので対応表で持つ。
_LIMIT_ATTR: dict[str, str] = {
    REQUEST: "requests",
    REDIRECT: "redirects",
    RETRY: "retries",
}

#: レート待機の分割幅（秒）。中断確認の粒度でもある。
WAIT_SLICE_SECONDS = 0.05

#: 通信タイムアウトの既定値（接続, 読み取り）。
DEFAULT_HTTP_TIMEOUT: tuple[float, float] = (3.05, 6.0)


class SchedulerError(Exception):
    """Scheduler の統制に違反した。"""


class BudgetExhausted(SchedulerError):
    """予算が尽きた。診断失敗ではなく被覆率の低下として扱う。"""


class TimeBudgetExhausted(BudgetExhausted):
    """Job 全体の制限時間を超えた。"""


class Cancelled(SchedulerError):
    """中断要求があった。"""


class ScopeViolation(SchedulerError):
    """許可されていない通信先に触れようとした。"""


@dataclass(frozen=True)
class Budgets:
    """予算設定。すべて 1 以上（秒は 0 より大）。"""

    requests: int = 300
    redirects: int = 30
    retries: int = 20
    seconds: float = 300.0
    per_host_interval: float = 0.5
    max_inflight: int = 2
    http_timeout: tuple[float, float] = DEFAULT_HTTP_TIMEOUT

    def __post_init__(self) -> None:
        for name in ("requests", "redirects", "retries", "max_inflight"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} は 1 以上の整数である必要があります: {value!r}")
        for name in ("seconds", "per_host_interval"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} は 0 より大きい必要があります: {value!r}")
        if len(self.http_timeout) != 2 or any(t <= 0 for t in self.http_timeout):
            raise ValueError("http_timeout は正の値2つ（接続, 読み取り）である必要があります")

    def limit_for(self, kind: str) -> int:
        return int(getattr(self, _LIMIT_ATTR[kind]))


@dataclass
class _Usage:
    request: int = 0
    redirect: int = 0
    retry: int = 0

    def add(self, kind: str, amount: int) -> None:
        setattr(self, kind, getattr(self, kind) + amount)

    def as_dict(self) -> dict[str, int]:
        return {kind: getattr(self, kind) for kind in KINDS}


class Scheduler:
    """1 Job 分の通信統制。Job ごとに1インスタンス生成する。"""

    def __init__(
        self,
        budgets: Budgets | None = None,
        *,
        scope: Callable[[str], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self._budgets = budgets or Budgets()
        self._scope = scope
        self._clock = clock
        self._sleep = sleeper
        self._cancel_event = cancel_event or threading.Event()

        self._lock = threading.Lock()
        self._usage = _Usage()
        self._started_at: float | None = None
        self._deadline: float | None = None
        self._last_host_at: dict[str, float] = {}
        self._inflight = threading.Semaphore(self._budgets.max_inflight)
        self._inflight_count = 0
        self._log: list[dict[str, Any]] = []
        self._cancel_reason: str | None = None
        self._budget_exhausted = False

    # --- 起動 -----------------------------------------------------------

    def start(self) -> None:
        """計時を開始する。二重呼び出しは無視する。"""
        with self._lock:
            if self._started_at is not None:
                return
            self._started_at = self._clock()
            self._deadline = self._started_at + float(self._budgets.seconds)

    # --- 予算 -----------------------------------------------------------

    def remaining(self, kind: str = REQUEST) -> int:
        if kind not in KINDS:
            raise ValueError(f"未知の予算種別: {kind}")
        with self._lock:
            return max(self._budgets.limit_for(kind) - getattr(self._usage, kind), 0)

    def try_reserve(self, kind: str = REQUEST, amount: int = 1) -> bool:
        """予算を確保できたら True。尽きていれば False（例外にしない）。"""
        if kind not in KINDS:
            raise ValueError(f"未知の予算種別: {kind}")
        if amount < 1:
            raise ValueError("amount は 1 以上である必要があります")

        with self._lock:
            limit = self._budgets.limit_for(kind)
            if getattr(self._usage, kind) + amount > limit:
                self._budget_exhausted = True
                return False
            self._usage.add(kind, amount)
            return True

    def reserve(self, kind: str = REQUEST, amount: int = 1) -> None:
        """予算を確保する。尽きていれば BudgetExhausted。"""
        if not self.try_reserve(kind, amount):
            raise BudgetExhausted(f"{kind} 予算が尽きました")

    @property
    def budget_exhausted(self) -> bool:
        """一度でも予算切れが起きたか。被覆率の算出に使う。"""
        with self._lock:
            return self._budget_exhausted

    def usage(self) -> dict[str, int]:
        with self._lock:
            return self._usage.as_dict()

    # --- 時間 -----------------------------------------------------------

    def remaining_seconds(self) -> float:
        if self._deadline is None:
            return float(self._budgets.seconds)
        return max(self._deadline - self._clock(), 0.0)

    def check_time(self) -> None:
        if self._deadline is not None and self._clock() >= self._deadline:
            raise TimeBudgetExhausted("Job の制限時間を超えました")

    def http_timeout(self) -> tuple[float, float]:
        """通信タイムアウト。残り時間が短ければ縮める。"""
        connect, read = self._budgets.http_timeout
        remaining = self.remaining_seconds()
        if remaining <= 0:
            raise TimeBudgetExhausted("残り時間がありません")
        return (min(connect, remaining), min(read, remaining))

    # --- 中断 -----------------------------------------------------------

    def cancel(self, reason: str | None = None) -> None:
        with self._lock:
            if self._cancel_reason is None:
                self._cancel_reason = reason or "利用者による中断"
        self._cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    @property
    def cancel_reason(self) -> str | None:
        return self._cancel_reason

    def check_cancel(self) -> None:
        if self._cancel_event.is_set():
            raise Cancelled(self._cancel_reason or "中断されました")

    # --- スコープ -------------------------------------------------------

    @property
    def scope_enforced(self) -> bool:
        return self._scope is not None

    def check_scope(self, target: str) -> None:
        """通信先が許可範囲か検証する。"""
        if self._scope is None:
            return
        if not self._scope(target):
            self.record("scope_violation", target=target)
            raise ScopeViolation(f"スコープ外です: {target}")

    # --- 同時実行とレート -----------------------------------------------

    def _wait_for_rate(self, host: str) -> None:
        interval = self._budgets.per_host_interval
        last = self._last_host_at.get(host)
        if last is None:
            self._last_host_at[host] = self._clock()
            return

        while True:
            wait = interval - (self._clock() - last)
            if wait <= 0:
                break
            self.check_cancel()
            self._sleep(min(wait, WAIT_SLICE_SECONDS))

        self._last_host_at[host] = self._clock()

    @contextmanager
    def slot(self, host: str) -> Iterator[None]:
        """レート待機と同時実行枠をまとめて確保する。

        通信はこのブロック内で行う。予算確保は別途 ``require`` で先に行う。
        """
        self.check_cancel()
        self.check_time()
        self._wait_for_rate(host)

        self._inflight.acquire()
        with self._lock:
            self._inflight_count += 1
        try:
            yield
        finally:
            with self._lock:
                self._inflight_count -= 1
            self._inflight.release()

    @property
    def inflight(self) -> int:
        with self._lock:
            return self._inflight_count

    # --- ログ -----------------------------------------------------------

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        """診断ログ1件を残す。秘密値は呼び出し側で落としてから渡す。"""
        entry = {"event": event, **fields}
        with self._lock:
            self._log.append(entry)
        return entry

    def log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._log)

    # --- 集計 -----------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """被覆率・ログに載せる現況。"""
        return {
            "usage": self.usage(),
            "remaining": {kind: self.remaining(kind) for kind in KINDS},
            "remaining_seconds": round(self.remaining_seconds(), 3),
            "inflight": self.inflight,
            "cancelled": self.cancelled,
            "cancel_reason": self.cancel_reason,
            "budget_exhausted": self.budget_exhausted,
            "scope_enforced": self.scope_enforced,
        }