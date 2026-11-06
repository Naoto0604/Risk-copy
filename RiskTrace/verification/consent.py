"""診断同意の記録。

所有証明とは別データとして管理する。証明が成立していても同意が無ければ
診断は始めない（§5.2 / §4.10）。

記録する内容（§5.2）:
    同意者 / 連絡先 / 同意日時 / 診断対象 / 対象範囲 /
    許可された診断機能 / 予算・レート制限 / 有効期限 / 撤回日時 / 状態

方針:
    - 同意はスコープを内包する。後段で証明対象との一致を機械的に検証できる
    - 予算は数値のまま保存し、engine への依存を作らない
    - 有効期限は必須。撤回は行削除ではなく状態遷移で残す
    - 許可機能は空にできない（何も動かせない同意は無意味）
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from database import db
from verification.scope import Scope, ScopeError

ACTIVE = "ACTIVE"
WITHDRAWN = "WITHDRAWN"
EXPIRED = "EXPIRED"

STATUSES: tuple[str, ...] = (ACTIVE, WITHDRAWN, EXPIRED)

DEFAULT_EXPIRY_DAYS = 30

BUDGET_KEYS: tuple[str, ...] = (
    "requests",
    "redirects",
    "retries",
    "seconds",
    "per_host_interval",
    "max_inflight",
)

DEFAULT_BUDGETS: dict[str, float] = {
    "requests": 300,
    "redirects": 30,
    "retries": 20,
    "seconds": 300,
    "per_host_interval": 0.5,
    "max_inflight": 2,
}


class ConsentError(Exception):
    """同意の記録内容が不正、または状態遷移が不正。"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class Consent:
    id: str
    grantor: str
    contact: str
    target: str
    scope: dict[str, Any]
    allowed_collectors: tuple[str, ...]
    budgets: dict[str, float]
    status: str
    granted_at: str
    expires_at: str
    withdrawn_at: str | None
    note: str | None

    @property
    def is_active(self) -> bool:
        return self.status == ACTIVE and _parse(self.expires_at) > _now()

    def build_scope(self) -> Scope:
        """保存済みスコープから ``Scope`` を復元する。"""
        return Scope(
            hosts=frozenset(self.scope["hosts"]),
            ports=frozenset(self.scope["ports"]),
            path_prefixes=tuple(self.scope.get("path_prefixes") or ("/",)),
            allow_private=bool(self.scope.get("allow_private", False)),
            private_cidrs=tuple(self.scope.get("private_cidrs") or ()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "grantor": self.grantor,
            "contact": self.contact,
            "target": self.target,
            "scope": self.scope,
            "allowed_collectors": list(self.allowed_collectors),
            "budgets": dict(self.budgets),
            "status": self.status,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "withdrawn_at": self.withdrawn_at,
            "note": self.note,
        }


def _row_to_consent(row: Any) -> Consent:
    return Consent(
        id=row["id"],
        grantor=row["grantor"],
        contact=row["contact"],
        target=row["target"],
        scope=json.loads(row["scope_json"]),
        allowed_collectors=tuple(json.loads(row["collectors_json"])),
        budgets=json.loads(row["budgets_json"]),
        status=row["status"],
        granted_at=row["granted_at"],
        expires_at=row["expires_at"],
        withdrawn_at=row["withdrawn_at"],
        note=row["note"],
    )


# --- スキーマ -----------------------------------------------------------


def init_consents(conn: Any = None) -> None:
    statuses_sql = ", ".join(f"'{status}'" for status in STATUSES)
    own = conn is None
    if own:
        conn = db.get_connection()

    try:
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS consents (
                id TEXT PRIMARY KEY,
                grantor TEXT NOT NULL,
                contact TEXT NOT NULL,
                target TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                collectors_json TEXT NOT NULL,
                budgets_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ({statuses_sql})),
                granted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                withdrawn_at TEXT,
                note TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_consents_target_status
                ON consents (target, status)
        """)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if own:
            conn.close()


# --- 検証 ---------------------------------------------------------------


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConsentError(f"{label} は空でない文字列である必要があります")
    return value.strip()


def _require_collectors(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not values:
        raise ConsentError("allowed_collectors は空でないリストである必要があります")
    result: list[str] = []
    for value in values:
        result.append(_require_text(value, "allowed_collectors の要素"))
    return tuple(result)


def _require_budgets(values: dict[str, Any] | None) -> dict[str, float]:
    merged = dict(DEFAULT_BUDGETS)
    if values:
        unknown = set(values) - set(BUDGET_KEYS)
        if unknown:
            raise ConsentError(f"未知の予算キー: {sorted(unknown)}")
        merged.update(values)

    for key, value in merged.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConsentError(f"予算 {key} は数値である必要があります")
        if value <= 0:
            raise ConsentError(f"予算 {key} は 0 より大きい必要があります")
    return {key: float(merged[key]) for key in BUDGET_KEYS}


def _require_scope(target: str, scope: Scope | dict[str, Any]) -> tuple[Scope, dict[str, Any]]:
    try:
        built = scope if isinstance(scope, Scope) else Scope(**scope)
    except (ScopeError, TypeError) as exc:
        raise ConsentError(f"スコープが不正です: {exc}") from exc

    if target.strip().lower().rstrip(".") not in built.hosts:
        raise ConsentError(f"target がスコープに含まれていません: {target}")

    return built, built.describe()


# --- 記録 ---------------------------------------------------------------


def grant(
    *,
    grantor: str,
    contact: str,
    target: str,
    scope: Scope | dict[str, Any],
    allowed_collectors: Iterable[str],
    budgets: dict[str, Any] | None = None,
    expires_in_days: int = DEFAULT_EXPIRY_DAYS,
    note: str | None = None,
) -> Consent:
    """同意を記録する。"""
    grantor = _require_text(grantor, "grantor")
    contact = _require_text(contact, "contact")
    target = _require_text(target, "target").lower().rstrip(".")

    if expires_in_days < 1:
        raise ConsentError("expires_in_days は 1 以上である必要があります")

    _scope, scope_dict = _require_scope(target, scope)
    collectors = _require_collectors(allowed_collectors)
    budget_values = _require_budgets(budgets)

    now = _now()
    consent = Consent(
        id=f"cns_{secrets.token_hex(8)}",
        grantor=grantor,
        contact=contact,
        target=target,
        scope=scope_dict,
        allowed_collectors=collectors,
        budgets=budget_values,
        status=ACTIVE,
        granted_at=_iso(now),
        expires_at=_iso(now + timedelta(days=expires_in_days)),
        withdrawn_at=None,
        note=note.strip() if isinstance(note, str) and note.strip() else None,
    )

    conn = db.get_connection()
    try:
        conn.execute("""
            INSERT INTO consents (
                id, grantor, contact, target, scope_json, collectors_json,
                budgets_json, status, granted_at, expires_at, withdrawn_at, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            consent.id, consent.grantor, consent.contact, consent.target,
            json.dumps(consent.scope, ensure_ascii=False),
            json.dumps(list(consent.allowed_collectors), ensure_ascii=False),
            json.dumps(consent.budgets, ensure_ascii=False),
            consent.status, consent.granted_at, consent.expires_at,
            consent.withdrawn_at, consent.note,
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return consent


def withdraw(consent_id: str, *, reason: str | None = None) -> None:
    """同意を撤回する。既に撤回済みなら ConsentError。"""
    conn = db.get_connection()
    try:
        cursor = conn.execute("""
            UPDATE consents
            SET status = ?, withdrawn_at = ?, note = COALESCE(?, note)
            WHERE id = ? AND status = ?
        """, (WITHDRAWN, _iso(_now()), reason, consent_id, ACTIVE))
        if cursor.rowcount != 1:
            raise ConsentError(f"有効な同意ではありません: {consent_id}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --- 照会 ---------------------------------------------------------------


def get_consent(consent_id: str) -> Consent | None:
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM consents WHERE id = ?", (consent_id,)).fetchone()
        return None if row is None else _row_to_consent(row)
    finally:
        conn.close()


def is_active(consent_id: str) -> bool:
    consent = get_consent(consent_id)
    return consent is not None and consent.is_active


def active_for(target: str) -> list[Consent]:
    """対象に対する有効な同意の一覧。"""
    normalized = _require_text(target, "target").lower().rstrip(".")
    conn = db.get_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM consents WHERE target = ? AND status = ?
            ORDER BY granted_at DESC
        """, (normalized, ACTIVE)).fetchall()
    finally:
        conn.close()

    return [c for c in (_row_to_consent(row) for row in rows) if c.is_active]


def expire_overdue() -> int:
    """期限切れを EXPIRED にする。更新件数を返す。"""
    conn = db.get_connection()
    try:
        cursor = conn.execute("""
            UPDATE consents SET status = ? WHERE status = ? AND expires_at <= ?
        """, (EXPIRED, ACTIVE, _iso(_now())))
        conn.commit()
        return cursor.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_consents(target: str | None = None) -> list[Consent]:
    conn = db.get_connection()
    try:
        if target is None:
            rows = conn.execute("SELECT * FROM consents ORDER BY granted_at ASC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM consents WHERE target = ? ORDER BY granted_at ASC",
                (target.strip().lower().rstrip("."),),
            ).fetchall()
        return [_row_to_consent(row) for row in rows]
    finally:
        conn.close()


def reset_consents() -> None:
    """テスト用。"""
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM consents")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()