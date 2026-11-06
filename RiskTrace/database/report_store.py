"""レポートと Finding の保存。

既存 `findings` テーブルとは別に持つ。旧 `findings` は NOT NULL 制約が
旧形式前提（type / url）で、v2 の Finding と形が合わないため。

方針:
    - レポートは payload を JSON で丸ごと保存する。列を増やしても壊れない
    - Finding は1件1行でも保存する。エクスポートと検索のため
    - 保存は1トランザクションに閉じる
    - 削除は scans に追随させる（ON DELETE CASCADE）
    - 秘密値は ReportModel に入っていないものだけを扱う

``load_report`` は dict を返す。テンプレートの属性参照は dict でも解決される。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from typing import Any

from database import db
from engine.rule_runner import Finding
from report.model import ReportModel


class ReportStoreError(Exception):
    """保存・取得に失敗した。"""
    #: レポートの保存期間（日）。Evidence 側の既定に合わせる。
DEFAULT_RETENTION_DAYS = 90

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _host_of(target: str) -> str:
    """比較用のホスト。スキーム・パス・大文字小文字を落とす。"""
    text = (target or "").strip()
    host = urlsplit(text).hostname if "://" in text else text.split("/", 1)[0]
    return (host or "").lower()

def init_reports(conn: Any = None) -> None:
    own = conn is None
    if own:
        conn = db.get_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports_v2 (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                host TEXT,
                overall INTEGER NOT NULL,
                level TEXT NOT NULL,
                coverage REAL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
        """)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(reports_v2)")}
        if "host" not in columns:
            conn.execute("ALTER TABLE reports_v2 ADD COLUMN host TEXT")
        for row in conn.execute(
            "SELECT scan_id, target FROM reports_v2 WHERE host IS NULL"
        ).fetchall():
            conn.execute(
                "UPDATE reports_v2 SET host = ? WHERE scan_id = ?",
                (_host_of(row["target"]), row["scan_id"]),
            )
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_v2_host_created
                ON reports_v2 (host, created_at)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                section TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                subject TEXT,
                evidence_ids TEXT NOT NULL DEFAULT '[]',
                count INTEGER NOT NULL DEFAULT 1,
                detail TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_v2_scan
                ON findings_v2 (scan_id)
        """)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if own:
            conn.close()

def save_report(
    scan_id: str,
    report: ReportModel,
    *,
    findings: tuple[Finding, ...] = (),
    low_confidence: tuple[Finding, ...] = (),
) -> None:
    """レポートと Finding を保存する。同じ scan_id は上書き。"""
    if not isinstance(scan_id, str) or not scan_id.strip():
        raise ReportStoreError("scan_id が空です")

    payload = json.dumps(report.to_dict(), ensure_ascii=False)
    host = _host_of(report.target)
    conn = db.get_connection()

    try:
        conn.execute(
            """
            INSERT INTO reports_v2
                (scan_id, target, host, overall, level, coverage, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                target = excluded.target,
                host = excluded.host,
                overall = excluded.overall,
                level = excluded.level,
                coverage = excluded.coverage,
                payload = excluded.payload,
                created_at = excluded.created_at
            """,
            (scan_id, report.target, host, report.overall, report.level, report.coverage,
             payload, _now()),
        )

        conn.execute("DELETE FROM findings_v2 WHERE scan_id = ?", (scan_id,))

        for section, items in (("finding", findings), ("low_confidence", low_confidence)):
            for item in items:
                conn.execute(
                    """
                    INSERT INTO findings_v2
                        (scan_id, section, rule_id, title, severity, confidence,
                         subject, evidence_ids, count, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, section, item.rule_id, item.title, item.severity,
                     item.confidence, item.subject,
                     json.dumps(list(item.evidence_ids), ensure_ascii=False), 1, None),
                )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def load_report(scan_id: str) -> dict | None:
    """保存済みのレポートを返す。無ければ None。"""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT payload FROM reports_v2 WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return json.loads(row[0])


def previous_for(target: str, *, exclude_scan_id: str) -> dict | None:
    """同じホストの直近のレポートから、比較用の要約だけ返す。

    比較元はホストで決める。スキーム・末尾スラッシュ・大文字小文字は無視する。
    同じ時刻なら scan_id の大きい方を採り、結果を再現可能にする。
    """
    host = _host_of(target)
    if not host:
        return None

    conn = db.get_connection()
    try:
        row = conn.execute(
            """
            SELECT scan_id, overall, level, target, created_at FROM reports_v2
            WHERE host = ? AND scan_id != ?
            ORDER BY created_at DESC, scan_id DESC LIMIT 1
            """,
            (host, exclude_scan_id),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return {
        "scan_id": row["scan_id"],
        "overall": row["overall"],
        "level": row["level"],
        "target": row["target"],
        "created_at": row["created_at"],
        "compared_on": "host",
    }

def findings_for(scan_id: str) -> list[dict]:
    """保存済み Finding を返す。エクスポート用。"""
    conn = db.get_connection()
    try:
        rows = conn.execute(
            """
            SELECT section, rule_id, title, severity, confidence, subject, evidence_ids
            FROM findings_v2 WHERE scan_id = ? ORDER BY id ASC
            """,
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            "section": row[0],
            "rule_id": row[1],
            "title": row[2],
            "severity": row[3],
            "confidence": row[4],
            "subject": row[5],
            "evidence_ids": json.loads(row[6]),
        }
        for row in rows
    ]


def purge_expired(
    *,
    now: datetime | None = None,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    """保存期間を過ぎたレポートを消す。消した件数を返す。

    Finding も同じ scan_id で消す。scans の行は実行履歴として残す。
    """
    if retention_days < 1:
        raise ReportStoreError("retention_days は 1 以上である必要があります")

    moment = now or datetime.now(timezone.utc)
    cutoff = (moment - timedelta(days=retention_days)).isoformat(timespec="seconds")

    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT scan_id FROM reports_v2 WHERE created_at < ?", (cutoff,)
        ).fetchall()
        scan_ids = [row["scan_id"] for row in rows]
        for scan_id in scan_ids:
            conn.execute("DELETE FROM findings_v2 WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM reports_v2 WHERE created_at < ?", (cutoff,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return len(scan_ids)