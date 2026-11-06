"""不変 Evidence Store。

Evidence は観測事実を追跡するための不変データ。保存後は上書きしない。
修正が必要なら新しい Evidence を作る。

方針:
    - ID は一意。保存後の UPDATE を書かない
    - 完全性は SHA-256 で検証できる。ただし暗号化ではない
    - ハッシュ対象は ID・時刻を除いた本文のみ（同一内容なら同一ハッシュ）
    - 保存前に秘密値を落とす（Observation 側のマスキングに加えた二重化）
    - Job / Observation と関連付ける
    - 保存期間を持ち、削除は明示操作にする

ハッシュは「壊れていないこと」の確認用であり、秘密情報の保護手段ではない。
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from database import db
from engine.observations import Observation, is_secret_name

DEFAULT_RETENTION_DAYS = 90

#: ハッシュ対象から除くキー（本文ではないもの）。
NON_CONTENT_KEYS = frozenset({"observation_id", "evidence_id", "usable", "created_at"})


class EvidenceError(Exception):
    """Evidence の保存・検証に失敗した。"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _canonical(value: Any) -> str:
    """キー順に依存しない JSON 文字列。"""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _strip_secrets(value: Any) -> Any:
    """秘密名のキーを落とす。Observation 側のマスキングに加えた二重化。"""
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if isinstance(key, str) and is_secret_name(key):
                result[key] = "<masked>"
            else:
                result[key] = _strip_secrets(child)
        return result
    if isinstance(value, (list, tuple)):
        return [_strip_secrets(item) for item in value]
    return value


def content_of(observation: Observation) -> dict[str, Any]:
    """ハッシュ対象の本文を作る。ID・時刻・usable は除く。"""
    payload = {
        "collector": observation.collector,
        "subject": observation.subject,
        "status": observation.status,
        "data": _strip_secrets(observation.data),
        "note": observation.note,
    }
    return payload


def digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Evidence:
    id: str
    job_id: str | None
    observation_id: str | None
    collector: str
    subject: str
    status: str
    payload: dict[str, Any]
    sha256: str
    created_at: str
    expires_at: str | None

    def verify(self) -> bool:
        """保存内容が改竄されていないか確認する。"""
        return digest(self.payload) == self.sha256

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "observation_id": self.observation_id,
            "collector": self.collector,
            "subject": self.subject,
            "status": self.status,
            "sha256": self.sha256,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "payload": self.payload,
        }


def _row_to_evidence(row: Any) -> Evidence:
    return Evidence(
        id=row["id"],
        job_id=row["job_id"],
        observation_id=row["observation_id"],
        collector=row["collector"],
        subject=row["subject"],
        status=row["status"],
        payload=json.loads(row["payload_json"]),
        sha256=row["sha256"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )


# --- スキーマ -----------------------------------------------------------


def init_evidence(conn: Any = None) -> None:
    own = conn is None
    if own:
        conn = db.get_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                job_id TEXT,
                observation_id TEXT,
                collector TEXT NOT NULL,
                subject TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_observation
                ON evidence (observation_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_job
                ON evidence (job_id)
        """)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if own:
            conn.close()


# --- 保存 ---------------------------------------------------------------


def save(
    observation: Observation,
    *,
    job_id: str | None = None,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> Evidence:
    """Observation を Evidence として保存し、関連付けた Observation を返す。

    呼び出し側は戻り値の ``evidence_id`` を使う。
    """
    if not isinstance(observation, Observation):
        raise EvidenceError("observation は Observation である必要があります")
    if retention_days < 1:
        raise EvidenceError("retention_days は 1 以上である必要があります")

    payload = content_of(observation)
    checksum = digest(payload)
    now = _now()

    record = Evidence(
        id=f"ev_{secrets.token_hex(12)}",
        job_id=job_id,
        observation_id=observation.observation_id,
        collector=observation.collector,
        subject=observation.subject,
        status=observation.status,
        payload=payload,
        sha256=checksum,
        created_at=_iso(now),
        expires_at=_iso(now + timedelta(days=retention_days)),
    )

    conn = db.get_connection()
    try:
        conn.execute("""
            INSERT INTO evidence (
                id, job_id, observation_id, collector, subject, status,
                payload_json, sha256, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.id, record.job_id, record.observation_id, record.collector,
            record.subject, record.status, _canonical(record.payload),
            record.sha256, record.created_at, record.expires_at,
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return record


def save_observation(
    observation: Observation,
    *,
    job_id: str | None = None,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> Observation:
    """保存して evidence_id を紐付けた Observation を返す。"""
    return observation.with_evidence(save(observation, job_id=job_id, retention_days=retention_days).id)


# --- 参照 ---------------------------------------------------------------


def get(evidence_id: str) -> Evidence | None:
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return None if row is None else _row_to_evidence(row)
    finally:
        conn.close()


def for_observation(observation_id: str) -> list[Evidence]:
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE observation_id = ? ORDER BY created_at ASC",
            (observation_id,),
        ).fetchall()
        return [_row_to_evidence(row) for row in rows]
    finally:
        conn.close()


def for_job(job_id: str) -> list[Evidence]:
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE job_id = ? ORDER BY created_at ASC", (job_id,)
        ).fetchall()
        return [_row_to_evidence(row) for row in rows]
    finally:
        conn.close()


def verify(evidence_id: str) -> bool:
    """保存済み Evidence の完全性を確認する。"""
    record = get(evidence_id)
    if record is None:
        raise EvidenceError(f"Evidence がありません: {evidence_id}")
    return record.verify()


def count() -> int:
    conn = db.get_connection()
    try:
        return int(conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"])
    finally:
        conn.close()


def purge_expired(*, now: datetime | None = None) -> int:
    """保存期間を過ぎた Evidence を削除する。削除件数を返す。"""
    conn = db.get_connection()
    try:
        cursor = conn.execute(
            "DELETE FROM evidence WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (_iso(now or _now()),),
        )
        conn.commit()
        return cursor.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reset_evidence() -> None:
    """テスト用。"""
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM evidence")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()