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
from datetime import datetime, timezone
from typing import Any

from database import db
from engine.rule_runner import Finding
from report.model import ReportModel


class ReportStoreError(Exception):
    """保存・取得に失敗した。"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_reports(conn: Any = None) -> None:
    own = conn is None
    if own:
        conn = db.get_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports_v2 (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
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
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_v2_target_created
                ON reports_v2 (target, created_at)
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
    conn = db.get_connection()

    try:
        conn.execute(
            """
            INSERT INTO reports_v2 (scan_id, target, overall, level, coverage, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                target = excluded.target,
                overall = excluded.overall,
                level = excluded.level,
                coverage = excluded.coverage,
                payload = excluded.payload,
                created_at = excluded.created_at
            """,
            (scan_id, report.target, report.overall, report.level, report.coverage,
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
    """同じ対象の直近のレポートから、比較用の要約だけ返す。"""
    conn = db.get_connection()
    try:
        row = conn.execute(
            """
            SELECT overall, level FROM reports_v2
            WHERE target = ? AND scan_id != ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (target, exclude_scan_id),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return {"overall": row[0], "level": row[1]}


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