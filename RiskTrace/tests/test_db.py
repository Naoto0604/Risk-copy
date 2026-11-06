import os
import tempfile
import unittest
from unittest.mock import patch

import database.db as db


class TestDatabaseConnection(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.db_dir_patcher = patch.object(
            db, "DB_DIR", self.temp_dir.name
        )
        self.db_path_patcher = patch.object(
            db,
            "DB_PATH",
            os.path.join(self.temp_dir.name, "test.db"),
        )
        self.wal_patcher = patch.object(
            db, "_wal_initialized", False
        )

        self.db_dir_patcher.start()
        self.db_path_patcher.start()
        self.wal_patcher.start()

    def tearDown(self):
        self.wal_patcher.stop()
        self.db_path_patcher.stop()
        self.db_dir_patcher.stop()
        self.temp_dir.cleanup()

    def test_foreign_keys_are_enabled(self):
        """各接続で外部キー制約が有効になっている。"""
        conn = db.get_connection()

        try:
            result = conn.execute(
                "PRAGMA foreign_keys"
            ).fetchone()[0]

            self.assertEqual(result, 1)
        finally:
            conn.close()

    def test_busy_timeout_is_configured(self):
        """ロック中の待機時間が設定されている。"""
        conn = db.get_connection()

        try:
            result = conn.execute(
                "PRAGMA busy_timeout"
            ).fetchone()[0]

            self.assertEqual(result, db.BUSY_TIMEOUT_MS)
        finally:
            conn.close()

    def test_wal_mode_is_enabled(self):
        """SQLiteがWALモードで動作する。"""
        conn = db.get_connection()

        try:
            result = conn.execute(
                "PRAGMA journal_mode"
            ).fetchone()[0]

            self.assertEqual(result.lower(), "wal")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()