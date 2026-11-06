from database.db import get_connection
from urllib.parse import urlparse
import json


# 選択可能な分析機能
DEFAULT_ANALYSIS_OPTIONS = [
    "score",
    "correlation",
    "attack_path",
    "priority",
]

ALLOWED_ANALYSIS_OPTIONS = set(DEFAULT_ANALYSIS_OPTIONS)

# デフォルトの診断項目
# ポート確認は通信を行うため、デフォルトでは有効にしない
DEFAULT_CHECK_OPTIONS = [
    "https",
    "headers",
    "cookies",
    "redirects",
]

# Webポート確認も選択可能な診断項目として許可する
ALLOWED_CHECK_OPTIONS = set(DEFAULT_CHECK_OPTIONS) | {"ports"}

# evidenceの最大サイズ
MAX_EVIDENCE_LENGTH = 10000


def validate_finding(finding):
    """FindingをDBに保存する前に入力値を検証する。"""
    if not isinstance(finding, dict):
        raise ValueError("Findingの形式が不正です")

    required_fields = ["type", "severity", "title", "url"]

    for field in required_fields:
        value = finding.get(field)

        if value is None:
            raise ValueError(f"Findingの必須項目が空です: {field}")

        if not isinstance(value, str):
            raise ValueError(f"Findingの値が不正です: {field}")

        if not value.strip():
            raise ValueError(f"Findingの必須項目が空です: {field}")

    # URLチェック
    parsed_url = urlparse(finding["url"])

    if parsed_url.scheme not in ("http", "https"):
        raise ValueError(
            f"FindingのURLが不正です: {finding['url']}"
        )

    if not parsed_url.netloc or not parsed_url.hostname:
        raise ValueError(
            f"FindingのURLにホスト名がありません: {finding['url']}"
        )

    # subtypeは省略可能。ただし指定する場合は文字列にする
    subtype = finding.get("subtype")

    if subtype is not None and not isinstance(subtype, str):
        raise ValueError("subtypeの形式が不正です")

    # evidenceチェック
    evidence = finding.get("evidence")

    if evidence is not None:
        if not isinstance(evidence, str):
            raise ValueError("evidenceの形式が不正です")

        if len(evidence) > MAX_EVIDENCE_LENGTH:
            raise ValueError("evidenceが大きすぎます")


def init_db():
    """
    RiskTraceのデータベースを初期化する。
    既存DBにも不足しているカラムを追加する。
    """
    conn = get_connection()

    try:
        cursor = conn.cursor()

        # Scanテーブルを作成
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                protocol TEXT,
                status TEXT NOT NULL,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                analysis_options TEXT NOT NULL
                    DEFAULT '["score", "correlation", "attack_path", "priority"]',
                checks_options TEXT NOT NULL
                    DEFAULT '["https", "headers", "cookies", "redirects"]'
            )
        """)

        # 既存scansテーブルのカラム一覧を取得
        cursor.execute("PRAGMA table_info(scans)")
        scan_columns = {
            row["name"] for row in cursor.fetchall()
        }

        # 既存DBにも不足しているカラムを追加
        # scan_columnsはALTER TABLE実行前の一覧なので、
        # 各カラムの存在を個別に確認する
        if "error_message" not in scan_columns:
            cursor.execute("""
                ALTER TABLE scans
                ADD COLUMN error_message TEXT
            """)

        if "analysis_options" not in scan_columns:
            cursor.execute("""
                ALTER TABLE scans
                ADD COLUMN analysis_options TEXT NOT NULL
                    DEFAULT '["score", "correlation", "attack_path", "priority"]'
            """)

        if "checks_options" not in scan_columns:
            cursor.execute("""
                ALTER TABLE scans
                ADD COLUMN checks_options TEXT NOT NULL
                    DEFAULT '["https", "headers", "cookies", "redirects"]'
            """)

        # Findingテーブルを作成
        # 新規DBでは最初からsubtypeを含める
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                type TEXT NOT NULL,
                subtype TEXT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                recommendation TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
        """)

        # 既存findingsテーブルのカラム一覧を取得
        cursor.execute("PRAGMA table_info(findings)")
        finding_columns = {
            row["name"] for row in cursor.fetchall()
        }

        # 既存DBにsubtypeがなければ追加
        if "subtype" not in finding_columns:
            cursor.execute("""
                ALTER TABLE findings
                ADD COLUMN subtype TEXT
            """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def create_scan(
    scan_id,
    target_url,
    protocol,
    status,
    analysis_options=None,
    checks_options=None,
):
    """Scan情報と選択された診断・分析機能をDBに保存する。"""
    if analysis_options is None:
        analysis_options = DEFAULT_ANALYSIS_OPTIONS

    if checks_options is None:
        checks_options = DEFAULT_CHECK_OPTIONS

    for name, options in (
        ("analysis_options", analysis_options),
        ("checks_options", checks_options),
    ):
        if (
            not isinstance(options, (list, tuple, set))
            or any(not isinstance(option, str) for option in options)
        ):
            raise ValueError(f"{name}の指定が不正です")

    # 許可された選択肢だけを保存する
    analysis_options = sorted(
        set(analysis_options) & ALLOWED_ANALYSIS_OPTIONS
    )

    checks_options = sorted(
        set(checks_options) & ALLOWED_CHECK_OPTIONS
    )

    analysis_json = json.dumps(
        analysis_options,
        ensure_ascii=False,
    )

    checks_json = json.dumps(
        checks_options,
        ensure_ascii=False,
    )

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scans (
                id,
                target_url,
                protocol,
                status,
                analysis_options,
                checks_options
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            target_url,
            protocol,
            status,
            analysis_json,
            checks_json,
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def update_scan_status(scan_id, status, error_message=None):
    """Scanのステータスとエラーメッセージを更新する。"""
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE scans
            SET status = ?, error_message = ?
            WHERE id = ?
        """, (
            status,
            error_message,
            scan_id,
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def create_finding(scan_id, finding):
    """Findingを1件DBに保存する。"""
    validate_finding(finding)

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO findings (
                scan_id,
                type,
                subtype,
                severity,
                title,
                url,
                description,
                evidence,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            finding.get("type"),
            finding.get("subtype"),
            finding.get("severity"),
            finding.get("title"),
            finding.get("url"),
            finding.get("description"),
            finding.get("evidence"),
            finding.get("recommendation"),
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def create_findings(scan_id, findings):
    """複数のFindingを検証してからDBにまとめて保存する。"""
    if findings is None:
        raise ValueError("Finding一覧がNoneです")

    if not isinstance(findings, list):
        raise ValueError("Finding一覧の形式が不正です")

    # DBに接続する前に全Findingを検証する
    for finding in findings:
        validate_finding(finding)

    conn = get_connection()

    try:
        cursor = conn.cursor()

        for finding in findings:
            cursor.execute("""
                INSERT INTO findings (
                    scan_id,
                    type,
                    subtype,
                    severity,
                    title,
                    url,
                    description,
                    evidence,
                    recommendation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                finding.get("type"),
                finding.get("subtype"),
                finding.get("severity"),
                finding.get("title"),
                finding.get("url"),
                finding.get("description"),
                finding.get("evidence"),
                finding.get("recommendation"),
            ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_scan(scan_id):
    """Scan情報を取得する。"""
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM scans
            WHERE id = ?
        """, (
            scan_id,
        ))

        return cursor.fetchone()

    finally:
        conn.close()


def get_findings(scan_id):
    """指定したScanのFinding一覧を取得する。"""
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
        """, (
            scan_id,
        ))

        return cursor.fetchall()

    finally:
        conn.close()