"""所有証明（DNS TXT 方式 / HTTP ファイル設置方式）。

どちらも「推測困難なトークンを対象に置かせ、読み戻して一致を確認する」。
一致しなければ証明は成立しない。

方針:
    - トークンは secrets で生成する
    - チャレンジには有効期限を設け、期限切れは検証しない
    - 証明成立後にも別の有効期限を設け、切れたら無効
    - 照合は完全一致
    - 通信は注入された fetch が行う（Scheduler 配下に置く前提）
    - トークンは設定画面には出すが、レポート用 dict には既定で含めない

サブドメインは自動的に証明済みにしない。host は完全一致で扱う。
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from database import db

DNS_TXT = "dns_txt"
HTTP_FILE = "http_file"

METHODS: tuple[str, ...] = (DNS_TXT, HTTP_FILE)

PENDING = "PENDING"
VERIFIED = "VERIFIED"
FAILED = "FAILED"
EXPIRED = "EXPIRED"

STATUSES: tuple[str, ...] = (PENDING, VERIFIED, FAILED, EXPIRED)

DEFAULT_CHALLENGE_TTL_HOURS = 24
DEFAULT_PROOF_TTL_DAYS = 30

TXT_RECORD_PREFIX = "_risktrace"
TXT_VALUE_PREFIX = "risktrace-verify="
FILE_DIRECTORY = "/.well-known/risktrace"
DOH_ENDPOINT = "https://dns.google/resolve"

#: 応答本文の上限。証明ファイルは小さい。
MAX_RESPONSE_CHARS = 8192

TOKEN_BYTES = 32


class ProofError(Exception):
    """証明の生成・検証に失敗した。"""


@dataclass(frozen=True)
class FetchResult:
    status: int
    text: str


#: ``fetch(url) -> FetchResult``。Scheduler を経由して実装する。
Fetcher = Callable[[str], FetchResult]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class Challenge:
    id: str
    host: str
    method: str
    token: str
    record_name: str
    file_url: str
    status: str
    created_at: str
    expires_at: str
    verified_at: str | None
    attempts: int
    last_error: str | None

    @property
    def is_valid(self) -> bool:
        return self.status == VERIFIED and _parse(self.expires_at) > _now()

    def setup_instructions(self) -> dict[str, Any]:
        """利用者に提示する設定内容。トークンを含む。"""
        if self.method == DNS_TXT:
            return {
                "method": DNS_TXT,
                "record_type": "TXT",
                "record_name": self.record_name,
                "record_value": TXT_VALUE_PREFIX + self.token,
            }
        return {"method": HTTP_FILE, "url": self.file_url, "body": self.token}

    def to_dict(self, *, include_token: bool = False) -> dict[str, Any]:
        """レポート・ログ用。既定ではトークンを伏せる。"""
        payload = {
            "id": self.id,
            "host": self.host,
            "method": self.method,
            "record_name": self.record_name,
            "file_url": self.file_url,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "verified_at": self.verified_at,
            "attempts": self.attempts,
            "last_error": self.last_error,
        }
        if include_token:
            payload["token"] = self.token
        return payload


def _row_to_challenge(row: Any) -> Challenge:
    return Challenge(
        id=row["id"],
        host=row["host"],
        method=row["method"],
        token=row["token"],
        record_name=row["record_name"],
        file_url=row["file_url"],
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        verified_at=row["verified_at"],
        attempts=row["attempts"],
        last_error=row["last_error"],
    )


# --- スキーマ -----------------------------------------------------------


def init_proofs(conn: Any = None) -> None:
    statuses_sql = ", ".join(f"'{status}'" for status in STATUSES)
    methods_sql = ", ".join(f"'{method}'" for method in METHODS)
    own = conn is None
    if own:
        conn = db.get_connection()

    try:
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS proofs (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                method TEXT NOT NULL CHECK (method IN ({methods_sql})),
                token TEXT NOT NULL,
                record_name TEXT NOT NULL,
                file_url TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ({statuses_sql})),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                verified_at TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_proofs_host_status
                ON proofs (host, status)
        """)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if own:
            conn.close()


# --- 生成 ---------------------------------------------------------------


def _require_host(host: str) -> str:
    if not isinstance(host, str) or not host.strip():
        raise ProofError("host は空でない文字列である必要があります")
    normalized = host.strip().lower().rstrip(".")
    if "/" in normalized or " " in normalized:
        raise ProofError(f"host が不正です: {host!r}")
    return normalized


def create_challenge(
    host: str,
    method: str,
    *,
    base_url: str | None = None,
    challenge_ttl_hours: int = DEFAULT_CHALLENGE_TTL_HOURS,
) -> Challenge:
    """チャレンジを作る。``method`` は DNS_TXT か HTTP_FILE。"""
    host = _require_host(host)

    if method not in METHODS:
        raise ProofError(f"未知の方式です: {method!r}")
    if challenge_ttl_hours < 1:
        raise ProofError("challenge_ttl_hours は 1 以上である必要があります")

    if method == HTTP_FILE:
        if not base_url:
            raise ProofError("HTTP_FILE 方式には base_url が必要です")
        base = base_url.rstrip("/")

    token = secrets.token_urlsafe(TOKEN_BYTES)
    now = _now()

    if method == DNS_TXT:
        record_name = f"{TXT_RECORD_PREFIX}.{host}"
        file_url = ""
    else:
        record_name = ""
        file_url = f"{base}{FILE_DIRECTORY}/{token}.txt"

    challenge = Challenge(
        id=f"prf_{secrets.token_hex(8)}",
        host=host,
        method=method,
        token=token,
        record_name=record_name,
        file_url=file_url,
        status=PENDING,
        created_at=_iso(now),
        expires_at=_iso(now + timedelta(hours=challenge_ttl_hours)),
        verified_at=None,
        attempts=0,
        last_error=None,
    )

    conn = db.get_connection()
    try:
        conn.execute("""
            INSERT INTO proofs (
                id, host, method, token, record_name, file_url, status,
                created_at, expires_at, verified_at, attempts, last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            challenge.id, challenge.host, challenge.method, challenge.token,
            challenge.record_name, challenge.file_url, challenge.status,
            challenge.created_at, challenge.expires_at, challenge.verified_at,
            challenge.attempts, challenge.last_error,
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return challenge


# --- 検証 ---------------------------------------------------------------


def get_challenge(proof_id: str) -> Challenge | None:
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM proofs WHERE id = ?", (proof_id,)).fetchone()
        return None if row is None else _row_to_challenge(row)
    finally:
        conn.close()


def _mark(proof_id: str, status: str, *, error: str | None, verified: bool = False) -> None:
    conn = db.get_connection()
    try:
        conn.execute("""
            UPDATE proofs
            SET status = ?, attempts = attempts + 1, last_error = ?,
                verified_at = COALESCE(?, verified_at)
            WHERE id = ?
        """, (status, error, _iso(_now()) if verified else None, proof_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _load_pending(proof_id: str, method: str) -> Challenge:
    challenge = get_challenge(proof_id)
    if challenge is None:
        raise ProofError(f"チャレンジがありません: {proof_id}")
    if challenge.method != method:
        raise ProofError(f"方式が一致しません: {challenge.method} != {method}")
    if challenge.status == VERIFIED and challenge.is_valid:
        return challenge
    if _parse(challenge.expires_at) <= _now():
        _mark(proof_id, EXPIRED, error="チャレンジの有効期限が切れています")
        raise ProofError("チャレンジの有効期限が切れています")
    return challenge


def _extract_txt_values(payload: str) -> list[str]:
    """DoH の JSON 応答から TXT の値を取り出す。"""
    try:
        document = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise ProofError("DNS 応答を解析できません") from exc

    if not isinstance(document, dict):
        raise ProofError("DNS 応答の形式が不正です")

    values: list[str] = []
    for answer in document.get("Answer") or []:
        if not isinstance(answer, dict):
            continue
        if answer.get("type") != 16:  # TXT
            continue
        data = answer.get("data")
        if isinstance(data, str):
            values.append(data.strip().strip('"'))
    return values


def verify_dns_txt(proof_id: str, fetch: Fetcher, *, proof_ttl_days: int = DEFAULT_PROOF_TTL_DAYS) -> bool:
    """TXT レコードを照会してトークンの一致を確認する。"""
    challenge = _load_pending(proof_id, DNS_TXT)

    url = f"{DOH_ENDPOINT}?name={challenge.record_name}&type=TXT"
    try:
        result = fetch(url)
    except Exception as exc:  # noqa: BLE001 - 失敗として記録する
        _mark(proof_id, FAILED, error=f"DNS 照会に失敗: {exc}")
        return False

    if result.status != 200:
        _mark(proof_id, FAILED, error=f"DNS 照会が HTTP {result.status}")
        return False

    expected = TXT_VALUE_PREFIX + challenge.token
    try:
        values = _extract_txt_values(result.text[:MAX_RESPONSE_CHARS])
    except ProofError as exc:
        _mark(proof_id, FAILED, error=str(exc))
        return False

    if expected not in values:
        _mark(proof_id, FAILED, error="TXT レコードが一致しません")
        return False

    _mark(proof_id, VERIFIED, error=None, verified=True)
    _extend_validity(proof_id, proof_ttl_days)
    return True


def verify_http_file(proof_id: str, fetch: Fetcher, *, proof_ttl_days: int = DEFAULT_PROOF_TTL_DAYS) -> bool:
    """設置ファイルを取得してトークンの一致を確認する。"""
    challenge = _load_pending(proof_id, HTTP_FILE)

    try:
        result = fetch(challenge.file_url)
    except Exception as exc:  # noqa: BLE001
        _mark(proof_id, FAILED, error=f"ファイル取得に失敗: {exc}")
        return False

    if result.status != 200:
        _mark(proof_id, FAILED, error=f"ファイル取得が HTTP {result.status}")
        return False

    body = result.text[:MAX_RESPONSE_CHARS].strip()
    if body != challenge.token:
        _mark(proof_id, FAILED, error="ファイル内容が一致しません")
        return False

    _mark(proof_id, VERIFIED, error=None, verified=True)
    _extend_validity(proof_id, proof_ttl_days)
    return True


def _extend_validity(proof_id: str, proof_ttl_days: int) -> None:
    """証明成立後の有効期限を設定する。"""
    if proof_ttl_days < 1:
        raise ProofError("proof_ttl_days は 1 以上である必要があります")

    conn = db.get_connection()
    try:
        conn.execute(
            "UPDATE proofs SET expires_at = ? WHERE id = ?",
            (_iso(_now() + timedelta(days=proof_ttl_days)), proof_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --- 照会 ---------------------------------------------------------------


def is_valid(host: str, method: str | None = None) -> bool:
    """有効な証明があるか。"""
    normalized = _require_host(host)
    sql = "SELECT status, expires_at FROM proofs WHERE host = ? AND status = ?"
    params: list[Any] = [normalized, VERIFIED]
    if method is not None:
        sql += " AND method = ?"
        params.append(method)

    conn = db.get_connection()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    return any(_parse(row["expires_at"]) > _now() for row in rows)


def expire_overdue() -> int:
    """期限切れを EXPIRED にする。更新件数を返す。"""
    now = _iso(_now())
    conn = db.get_connection()
    try:
        cursor = conn.execute("""
            UPDATE proofs SET status = ?
            WHERE status IN (?, ?) AND expires_at <= ?
        """, (EXPIRED, PENDING, VERIFIED, now))
        conn.commit()
        return cursor.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_proofs(host: str | None = None) -> list[Challenge]:
    conn = db.get_connection()
    try:
        if host is None:
            rows = conn.execute("SELECT * FROM proofs ORDER BY created_at ASC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM proofs WHERE host = ? ORDER BY created_at ASC",
                (_require_host(host),),
            ).fetchall()
        return [_row_to_challenge(row) for row in rows]
    finally:
        conn.close()


def reset_proofs() -> None:
    """テスト用。"""
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM proofs")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()