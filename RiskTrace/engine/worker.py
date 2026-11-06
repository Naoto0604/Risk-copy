"""Job を取得して Collector 群を実行する Worker。

責務は「キューから取る・実行する・状態を戻す」だけ。判定はしない。

安全側の判断:
    - lease を失ったら finish しない（別 Worker が所有している可能性がある）
    - 利用者中断も finish しない。状態は CANCELLED のまま残す
      （finish は RUNNING を条件にしているため、上書きすると中断の事実が消える）
    - 予算切れ・スコープ逸脱は PARTIAL。部分結果は残す
    - 想定外の例外だけ FAILED。トレースバックは握りつぶさずログに残す
    - heartbeat は別スレッドで打ち続ける
    - 停止要求は現在の Job を終えてから効く

heartbeat スレッドの確認順は「状態 → 所有 → lease 更新」。
``queue.cancel()`` は lease も消すため、順序を誤ると中断が lease 失効として
扱われてしまう。

Worker 数は SQLite の単一 Writer 制約に合わせて上限を設ける（queue.WORKER_LIMIT）。
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from database import queue
from engine.scheduler import Budgets, BudgetExhausted, Cancelled, Scheduler, ScopeViolation


@dataclass(frozen=True)
class RunResult:
    """Runner の戻り値。既定は正常完了。"""

    status: str = queue.COMPLETED
    note: str | None = None

    def __post_init__(self) -> None:
        if self.status not in (queue.COMPLETED, queue.PARTIAL):
            raise ValueError(f"Runner が返せる状態は COMPLETED / PARTIAL のみ: {self.status}")


#: ``runner(job, scheduler) -> RunResult | None``。None は COMPLETED 扱い。
Runner = Callable[[Any, Scheduler], "RunResult | None"]


class Worker:
    def __init__(
        self,
        runner: Runner,
        *,
        worker_id: str | None = None,
        budgets: Budgets | None = None,
        scope: Callable[[str], bool] | None = None,
        lease_seconds: int = 60,
        heartbeat_interval: float | None = None,
        scheduler_factory: Callable[[Scheduler], None] | None = None,
    ) -> None:
        if not callable(runner):
            raise TypeError("runner は呼び出し可能である必要があります")
        if lease_seconds < 2:
            raise ValueError("lease_seconds は 2 以上である必要があります")

        self.runner = runner
        self.worker_id = worker_id or f"worker_{uuid.uuid4().hex}"
        self.budgets = budgets or Budgets()
        self.scope = scope
        self.lease_seconds = lease_seconds
        self.heartbeat_interval = heartbeat_interval or max(lease_seconds / 3, 0.01)
        self._scheduler_factory = scheduler_factory

        self._stop = threading.Event()
        self._current: Any = None
        self._active_scheduler: Scheduler | None = None
        self._lease_lost = False
        self._job_cancelled = False
        self._log: list[dict[str, Any]] = []

    # --- 状態 -----------------------------------------------------------

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    @property
    def current_job(self) -> Any:
        return self._current

    def log(self) -> list[dict[str, Any]]:
        return list(self._log)

    def _record(self, event: str, **fields: Any) -> None:
        self._log.append({"event": event, **fields})

    # --- 制御 -----------------------------------------------------------

    def stop(self) -> None:
        """現在の Job を終えたらループを抜ける。"""
        self._stop.set()

    def cancel_current(self, reason: str | None = None) -> None:
        """実行中の Job に中断を要求する。"""
        scheduler = self._active_scheduler
        if scheduler is not None:
            scheduler.cancel(reason or "利用者による中断")

    # --- 実行 -----------------------------------------------------------

    def _new_scheduler(self) -> Scheduler:
        scheduler = Scheduler(self.budgets, scope=self.scope)
        if self._scheduler_factory is not None:
            self._scheduler_factory(scheduler)
        scheduler.start()
        return scheduler

    def _heartbeat_loop(self, job: Any, scheduler: Scheduler, done: threading.Event) -> None:
        """heartbeat を打ちながら状態と所有を監視する。

        heartbeat の失敗は「中断された」か「lease を失った」の2通りある。
        状態を読んでから heartbeat を打つまでの間に cancel が入り得るため、
        失敗時は必ず状態を読み直して切り分ける。
        """
        while not done.wait(self.heartbeat_interval):
            current = queue.get_job(job.id)

            if current is None:
                self._lease_lost = True
                self._record("lease_lost", job_id=job.id, reason="job_missing")
                scheduler.cancel("Job が失われました")
                return

            if current.status == queue.CANCELLED:
                self._job_cancelled = True
                self._record("job_cancelled", job_id=job.id)
                scheduler.cancel("利用者による中断")
                return

            if current.status != queue.RUNNING or current.worker_id != self.worker_id:
                self._lease_lost = True
                self._record("lease_lost", job_id=job.id, reason="not_owner")
                scheduler.cancel("lease 失効")
                return

            if queue.heartbeat(job.id, self.worker_id, lease_seconds=self.lease_seconds):
                continue

            # 直前に cancel された可能性がある。読み直してから決める。
            latest = queue.get_job(job.id)
            if latest is not None and latest.status == queue.CANCELLED:
                self._job_cancelled = True
                self._record("job_cancelled", job_id=job.id, reason="during_heartbeat")
                scheduler.cancel("利用者による中断")
                return

            self._lease_lost = True
            self._record("lease_lost", job_id=job.id, reason="heartbeat_failed")
            scheduler.cancel("lease 失効")
            return
                    
    def process(self, job: Any) -> str:
        """1 Job を実行し、確定した状態を返す。

        中断・lease 失効時は finish しない。どちらも既に状態が動いている。
        """
        scheduler = self._new_scheduler()
        self._active_scheduler = scheduler
        self._current = job
        self._lease_lost = False
        self._job_cancelled = False

        done = threading.Event()
        beat = threading.Thread(
            target=self._heartbeat_loop,
            args=(job, scheduler, done),
            name=f"hb-{job.id}",
            daemon=True,
        )
        beat.start()

        try:
            result = self.runner(job, scheduler)
            if result is None:
                result = RunResult()
            status, note = result.status, result.note
        except Cancelled as exc:
            status, note = queue.PARTIAL, f"中断: {exc}"
        except BudgetExhausted as exc:
            status, note = queue.PARTIAL, f"予算切れ: {exc}"
        except ScopeViolation as exc:
            status, note = queue.PARTIAL, f"スコープ逸脱: {exc}"
        except Exception as exc:  # noqa: BLE001 - 記録して FAILED にする
            status, note = queue.FAILED, f"{type(exc).__name__}: {exc}"
            self._record("runner_error", job_id=job.id, error=note)
        finally:
            done.set()
            beat.join(timeout=self.heartbeat_interval + 1)
            self._active_scheduler = None

        if self._job_cancelled:
            self._record("skip_finish", job_id=job.id, reason="cancelled")
            self._current = None
            return queue.CANCELLED

        if self._lease_lost:
            self._record("skip_finish", job_id=job.id, reason="lease_lost")
            self._current = None
            return queue.RUNNING

        try:
            queue.finish(job.id, status, error=note)
        except queue.QueueError as exc:
            self._record("finish_rejected", job_id=job.id, error=str(exc))
        finally:
            self._current = None

        self._record("job_finished", job_id=job.id, status=status)
        return status

    def run_once(self) -> str | None:
        """QUEUED が1件あれば実行する。無ければ None。"""
        job = queue.claim_next(self.worker_id, lease_seconds=self.lease_seconds)
        if job is None:
            return None
        return self.process(job)

    def run_forever(self, poll_interval: float = 0.5) -> None:
        """停止要求まで Job を処理し続ける。"""
        if poll_interval <= 0:
            raise ValueError("poll_interval は 0 より大きい必要があります")

        queue.register_worker(self.worker_id)
        self._stop.clear()
        try:
            while not self._stop.is_set():
                job = queue.claim_next(self.worker_id, lease_seconds=self.lease_seconds)
                if job is None:
                    if self._stop.wait(poll_interval):
                        break
                    continue
                self.process(job)
        finally:
            queue.unregister_worker(self.worker_id)