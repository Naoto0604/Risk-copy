"""SQLite ベースの Job キュー。

単一ホスト・小規模運用を前提とする。Redis 等は導入しない。

排他制御の方針:
    - 取得は ``BEGIN IMMEDIATE`` で書き込みロックを先に取る
    - 取得 UPDATE の rowcount でも二重取得を確認する（二段構え）
    - 状態遷移は必ず許可元の状態を WHERE に含める
    - 書き込みは短いトランザクションに閉じる

順序の方針:
    - FIFO は ``created_at ASC, rowid ASC`` の二段で決める。
      ``created_at`` はマイクロ秒精度で記録し、同一時刻の同着は
      ``rowid``（挿入順）で解決する
    - 索引は ``(status, created_at)``。``rowid`` は索引定義に書けないため、
      同着の解決だけに使う

復旧の方針:
    - heartbeat が失効した RUNNING は再開可能な状態へ戻す
    - 試行上限に達したものは FAILED にする（無限ループ防止）
    - 起動時は全 RUNNING を対象にできる（単一ホスト前提）
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from database import db

QUEUED = "QUEUED"
RUNNING = "RUNNING"
PAUSED = "PAUSED"
COMPLETED = "COMPLETED"
PARTIAL = "PARTIAL"
FAILED = "FAILED"
CANCELLED = "CANCELLED"

STATUSES: tuple[str, ...] = (QUEUED, RUNNING, PAUSED, COMPLETED, PARTIAL, FAILED, CANCELLED)

#: 再開できる状態。
RESUMABLE: frozenset[str] = frozenset({QUEUED, PAUSED})

#: 終了状態。以降の遷移はない。
TERMINAL: frozenset[str] = frozenset({COMPLETED, PARTIAL, FAILED, CANCELLED})

#: 実行中とみなす状態。
ACTIVE: frozenset[str] = frozenset({RUNNING})

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_LEASE_SECONDS = 60

#: SQLite の単一 Writer 制約を踏まえた Worker 上限。
WORKER_LIMIT = 2

#: FIFO の主キー。同着は rowid で解決する。
_OLDEST_FIRST = "created_at ASC, rowid ASC"


class QueueError(Exception):
    """キューの状態遷移が不正、または排他に失敗した。"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    """比較可能な ISO8601（UTC・マイクロ秒精度）に落とす。"""
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _new_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


@dataclass(frozen=True)
class Job:
    id: str
    scan_id: str
    status: str
    worker_id: str | None
    run_token: str | None
    attempts: int
    max_attempts: int
    heartbeat_at: str | None
    lease_expires_at: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    last_error: str | None

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL

    @property
    def can_resume(self) -> bool:
        return self.status in RESUMABLE

    @property
    def attempts_left(self) -> int:
        return max(self.max_attempts - self.attempts, 0)


def _row_to_job(row: Any) -> Job:
    return Job(
        id=row["id"],
        scan_id=row["scan_id"],
        status=row["status"],
        worker_id=row["worker_id"],
        run_token=row["run_token"],
        attempts=row["attempts"],
        max_attempts=row["max_attempts"],
        heartbeat_at=row["heartbeat_at"],
        lease_expires_at=row["lease_expires_at"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        last_error=row["last_error"],
    )


# --- スキーマ -----------------------------------------------------------


def init_queue(conn: Any = None) -> None:
    """キュー用テーブルを作成する。既存テーブルは触らない。"""
    statuses_sql = ", ".join(f"'{status}'" for status in STATUSES)
    own = conn is None
    if own:
        conn = db.get_connection()

    try:
        cursor = conn.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ({statuses_sql})),
                worker_id TEXT,
                run_token TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT {DEFAULT_MAX_ATTEMPTS},
                heartbeat_at TEXT,
                lease_expires_at TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                last_error TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_jobs_status_created
                ON jobs (status, created_at)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_jobs_scan
                ON jobs (scan_id)
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workers (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                current_job_id TEXT,
                started_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL
            )
        """)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if own:
            conn.close()


# --- 投入 ---------------------------------------------------------------


def enqueue(scan_id: str, *, job_id: str | None = None, max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> str:
    """Job を QUEUED で投入し、Job ID を返す。

    ``job_id`` を明示すると再投入の重複を検出できる。
    """
    if not isinstance(scan_id, str) or not scan_id.strip():
        raise QueueError("scan_id は空でない文字列である必要があります")
    if max_attempts < 1:
        raise QueueError("max_attempts は 1 以上である必要があります")

    job_id = job_id or _new_id("job_")
    conn = db.get_connection()

    try:
        conn.execute("""
            INSERT INTO jobs (id, scan_id, status, created_at, max_attempts)
            VALUES (?, ?, ?, ?, ?)
        """, (job_id, scan_id, QUEUED, _iso(_now()), max_attempts))
        conn.commit()
        return job_id
    except Exception as exc:
        conn.rollback()
        if "UNIQUE" in str(exc):
            raise QueueError(f"Job ID が既に存在します: {job_id}") from exc
        raise
    finally:
        conn.close()


# --- 取得 ---------------------------------------------------------------


def claim_next(worker_id: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> Job | None:
    """QUEUED の最も古い Job を排他的に取得する。無ければ None。"""
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise QueueError("worker_id は空でない文字列である必要があります")
    if lease_seconds < 1:
        raise QueueError("lease_seconds は 1 以上である必要があります")

    conn = db.get_connection()
    conn.isolation_level = None  # トランザクションを明示制御する

    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(f"""
            SELECT id FROM jobs
            WHERE status = ?
            ORDER BY {_OLDEST_FIRST}
            LIMIT 1
        """, (QUEUED,)).fetchone()

        if row is None:
            conn.execute("COMMIT")
            return None

        job_id = row["id"]
        now = _now()
        run_token = _new_id("run_")

        cursor = conn.execute("""
            UPDATE jobs
            SET status = ?,
                worker_id = ?,
                run_token = ?,
                attempts = attempts + 1,
                started_at = COALESCE(started_at, ?),
                heartbeat_at = ?,
                lease_expires_at = ?
            WHERE id = ? AND status = ?
        """, (
            RUNNING,
            worker_id,
            run_token,
            _iso(now),
            _iso(now),
            _iso(now + timedelta(seconds=lease_seconds)),
            job_id,
            QUEUED,
        ))

        if cursor.rowcount != 1:
            # BEGIN IMMEDIATE 下では通常起きない。起きたら取得をやり直させる。
            conn.execute("ROLLBACK")
            return None

        claimed = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        conn.execute("COMMIT")
        return _row_to_job(claimed)

    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


# --- 稼働維持 -----------------------------------------------------------


def heartbeat(job_id: str, worker_id: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> bool:
    """RUNNING の Job の lease を延長する。更新できたら True。"""
    now = _now()
    conn = db.get_connection()

    try:
        cursor = conn.execute("""
            UPDATE jobs
            SET heartbeat_at = ?, lease_expires_at = ?
            WHERE id = ? AND status = ? AND worker_id = ?
        """, (
            _iso(now),
            _iso(now + timedelta(seconds=lease_seconds)),
            job_id,
            RUNNING,
            worker_id,
        ))
        conn.commit()
        return cursor.rowcount == 1
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --- 終了 ---------------------------------------------------------------


def finish(job_id: str, status: str, *, error: str | None = None) -> None:
    """RUNNING の Job を終了状態へ移す。

    ``PARTIAL`` / ``FAILED`` でも部分結果は既に保存済みという前提で扱う。
    """
    if status not in TERMINAL:
        raise QueueError(f"終了状態ではありません: {status}")

    conn = db.get_connection()

    try:
        cursor = conn.execute("""
            UPDATE jobs
            SET status = ?, finished_at = ?, last_error = ?, lease_expires_at = NULL
            WHERE id = ? AND status = ?
        """, (status, _iso(_now()), error, job_id, RUNNING))

        if cursor.rowcount != 1:
            raise QueueError(f"Job は RUNNING ではありません: {job_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def pause(job_id: str, *, reason: str | None = None) -> None:
    """RUNNING の Job を PAUSED にする。"""
    conn = db.get_connection()
    try:
        cursor = conn.execute("""
            UPDATE jobs
            SET status = ?, lease_expires_at = NULL, last_error = COALESCE(?, last_error)
            WHERE id = ? AND status = ?
        """, (PAUSED, reason, job_id, RUNNING))
        if cursor.rowcount != 1:
            raise QueueError(f"Job は RUNNING ではありません: {job_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def resume(job_id: str) -> None:
    """PAUSED の Job を QUEUED に戻す。"""
    conn = db.get_connection()
    try:
        cursor = conn.execute("""
            UPDATE jobs SET status = ? WHERE id = ? AND status = ?
        """, (QUEUED, job_id, PAUSED))
        if cursor.rowcount != 1:
            raise QueueError(f"Job は PAUSED ではありません: {job_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cancel(job_id: str, *, reason: str | None = None) -> None:
    """未終了の Job を CANCELLED にする。"""
    conn = db.get_connection()
    try:
        cursor = conn.execute("""
            UPDATE jobs
            SET status = ?, finished_at = ?, last_error = COALESCE(?, last_error),
                lease_expires_at = NULL
            WHERE id = ? AND status IN (?, ?, ?)
        """, (CANCELLED, _iso(_now()), reason, job_id, QUEUED, RUNNING, PAUSED))
        if cursor.rowcount != 1:
            raise QueueError(f"Job は既に終了しています: {job_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --- 復旧 ---------------------------------------------------------------


def _requeue(job_id: str, attempts: int, max_attempts: int) -> str:
    """失効 Job を再開可能状態か FAILED に落とし、落とした先を返す。"""
    exhausted = attempts >= max_attempts
    status = FAILED if exhausted else QUEUED
    note = "試行上限に達したため中断" if exhausted else "heartbeat 失効のため再投入"

    conn = db.get_connection()
    try:
        conn.execute("""
            UPDATE jobs
            SET status = ?, worker_id = NULL, lease_expires_at = NULL,
                heartbeat_at = NULL, last_error = ?, finished_at = ?
            WHERE id = ? AND status = ?
        """, (status, note, _iso(_now()) if exhausted else None, job_id, RUNNING))
        conn.commit()
        return status
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def release_stale(*, now: datetime | None = None) -> list[tuple[str, str]]:
    """lease が切れた RUNNING Job を回収する。稼働中でも呼んでよい。

    戻り値は ``(job_id, 新しい状態)`` の一覧。
    """
    cutoff = _iso(now or _now())

    conn = db.get_connection()
    try:
        rows = conn.execute(f"""
            SELECT id, attempts, max_attempts FROM jobs
            WHERE status = ? AND (lease_expires_at IS NULL OR lease_expires_at < ?)
            ORDER BY {_OLDEST_FIRST}
        """, (RUNNING, cutoff)).fetchall()
    finally:
        conn.close()

    return [(row["id"], _requeue(row["id"], row["attempts"], row["max_attempts"])) for row in rows]


def recover_all_running() -> list[tuple[str, str]]:
    """起動時に全 RUNNING を回収する（単一ホスト前提）。

    稼働中の Worker がいる環境で呼ぶと実行中の Job を奪う。
    """
    conn = db.get_connection()
    try:
        rows = conn.execute(f"""
            SELECT id, attempts, max_attempts FROM jobs
            WHERE status = ?
            ORDER BY {_OLDEST_FIRST}
        """, (RUNNING,)).fetchall()
    finally:
        conn.close()

    return [(row["id"], _requeue(row["id"], row["attempts"], row["max_attempts"])) for row in rows]


# --- Worker 管理 --------------------------------------------------------


def register_worker(worker_id: str) -> None:
    now = _iso(_now())
    conn = db.get_connection()
    try:
        conn.execute("""
            INSERT INTO workers (id, status, started_at, heartbeat_at)
            VALUES (?, 'idle', ?, ?)
            ON CONFLICT(id) DO UPDATE SET status = 'idle', heartbeat_at = excluded.heartbeat_at
        """, (worker_id, now, now))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def touch_worker(worker_id: str, *, current_job_id: str | None = None) -> None:
    conn = db.get_connection()
    try:
        conn.execute("""
            UPDATE workers SET status = ?, current_job_id = ?, heartbeat_at = ?
            WHERE id = ?
        """, (RUNNING if current_job_id else "idle", current_job_id, _iso(_now()), worker_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def unregister_worker(worker_id: str) -> None:
    conn = db.get_connection()
    try:
        conn.execute("""
            UPDATE workers SET status = 'stopped', current_job_id = NULL, heartbeat_at = ?
            WHERE id = ?
        """, (_iso(_now()), worker_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_worker(worker_id: str) -> dict[str, Any] | None:
    """Worker の登録状態を返す。未登録なら None。"""
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM workers WHERE id = ?", (worker_id,)).fetchone()
        return None if row is None else dict(row)
    finally:
        conn.close()


def count_active_workers() -> int:
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT COUNT(*) AS n FROM workers WHERE status = ?", (RUNNING,)).fetchone()
        return int(row["n"])
    finally:
        conn.close()


def can_start_worker() -> bool:
    """Worker 上限に余裕があるか。"""
    return count_active_workers() < WORKER_LIMIT


# --- 参照 ---------------------------------------------------------------


def get_job(job_id: str) -> Job | None:
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return None if row is None else _row_to_job(row)
    finally:
        conn.close()


def list_jobs(status: str | None = None) -> list[Job]:
    conn = db.get_connection()
    try:
        if status is None:
            rows = conn.execute(f"SELECT * FROM jobs ORDER BY {_OLDEST_FIRST}").fetchall()
        else:
            rows = conn.execute(
                f"SELECT * FROM jobs WHERE status = ? ORDER BY {_OLDEST_FIRST}", (status,)
            ).fetchall()
        return [_row_to_job(row) for row in rows]
    finally:
        conn.close()


def count_by_status() -> dict[str, int]:
    conn = db.get_connection()
    try:
        rows = conn.execute("SELECT status, COUNT(*) AS n FROM jobs GROUP BY status").fetchall()
        counts = {status: 0 for status in STATUSES}
        for row in rows:
            counts[row["status"]] = int(row["n"])
        return counts
    finally:
        conn.close()


def reset_queue() -> None:
    """テスト用。jobs と workers を空にする。"""
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM jobs")
        conn.execute("DELETE FROM workers")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()