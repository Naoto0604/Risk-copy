import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import database.models as models


class TestFindingSubtypePersistence(unittest.TestCase):

    def setUp(self):
        # テストごとに独立した一時データベースを使用する
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(
            self.temp_dir.name,
            "risktrace_test.db",
        )

        self.connection_patcher = patch(
            "database.models.get_connection",
            side_effect=self._connect,
        )
        self.connection_patcher.start()

        # subtype追加前の既存DBを再現する
        conn = self._connect()

        try:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE scans (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    protocol TEXT,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    type TEXT NOT NULL,
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

            conn.commit()

        finally:
            conn.close()

        # 既存DBへのカラム追加もここで確認する
        models.init_db()

    def tearDown(self):
        self.connection_patcher.stop()
        self.temp_dir.cleanup()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _create_scan(self, scan_id):
        models.create_scan(
            scan_id=scan_id,
            target_url="https://example.test/",
            protocol="https",
            status="COMPLETED",
        )

    def _finding(self, title, subtype=None):
        finding = {
            "type": "SECURITY_HEADER",
            "severity": "MEDIUM",
            "title": title,
            "url": "https://example.test/",
            "description": "テスト用Finding",
            "evidence": "テスト用Evidence",
            "recommendation": "設定を確認する",
        }

        if subtype is not None:
            finding["subtype"] = subtype

        return finding

    def test_existing_database_gets_subtype_column(self):
        """既存DBにsubtypeカラムが追加される。"""
        conn = self._connect()

        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(findings)")
            columns = {
                row["name"]
                for row in cursor.fetchall()
            }
        finally:
            conn.close()

        self.assertIn("subtype", columns)

    def test_single_finding_preserves_subtype(self):
        """1件保存したFindingのsubtypeが保持される。"""
        self._create_scan("scan-single")

        models.create_finding(
            "scan-single",
            self._finding(
                "HSTSが設定されていません",
                "Strict-Transport-Security",
            ),
        )

        findings = models.get_findings("scan-single")

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["subtype"],
            "Strict-Transport-Security",
        )

    def test_multiple_findings_preserve_subtypes(self):
        """複数件まとめて保存してもsubtypeが保持される。"""
        self._create_scan("scan-multiple")

        models.create_findings(
            "scan-multiple",
            [
                self._finding(
                    "HSTSの設定不足",
                    "Strict-Transport-Security",
                ),
                self._finding(
                    "X-Frame-Optionsの設定不足",
                    "X-Frame-Options",
                ),
            ],
        )

        findings = models.get_findings("scan-multiple")

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            findings[0]["subtype"],
            "Strict-Transport-Security",
        )
        self.assertEqual(
            findings[1]["subtype"],
            "X-Frame-Options",
        )

    def test_finding_without_subtype_is_supported(self):
        """subtypeがない旧形式のFindingも保存できる。"""
        self._create_scan("scan-legacy")

        models.create_finding(
            "scan-legacy",
            self._finding("旧形式のFinding"),
        )

        findings = models.get_findings("scan-legacy")

        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["subtype"])



    def test_scan_error_message_is_saved(self):
        """診断失敗時のエラーメッセージがDBに保存される。"""
        self._create_scan("scan-failed")

        expected_message = "診断失敗のテスト"

        models.update_scan_status(
            "scan-failed",
            "FAILED",
            expected_message,
        )

        scan = models.get_scan("scan-failed")

        self.assertEqual(scan["status"], "FAILED")
        self.assertEqual(
            scan["error_message"],
            expected_message,
        )
        
if __name__ == "__main__":
    unittest.main()