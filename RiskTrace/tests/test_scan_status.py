import unittest
from unittest.mock import patch

import app as app_module


class TestScanStatus(unittest.TestCase):

    def setUp(self):
        self.client = app_module.app.test_client()

    def test_failed_status_includes_error_message(self):
        """FAILEDのステータスとエラーメッセージが返る。"""
        error_message = "診断処理に失敗しました（RuntimeError）。"

        scan = {
            "status": "FAILED",
            "error_message": error_message,
        }

        with patch.object(
            app_module,
            "get_scan",
            return_value=scan,
        ):
            response = self.client.get("/status/test-scan")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(
            data["error_message"],
            error_message,
        )

    def test_completed_status_has_no_error_message(self):
        """正常終了時もステータスAPIの形式が正しい。"""
        scan = {
            "status": "COMPLETED",
            "error_message": None,
        }

        with patch.object(
            app_module,
            "get_scan",
            return_value=scan,
        ):
            response = self.client.get("/status/test-scan")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["status"], "COMPLETED")
        self.assertIsNone(data["error_message"])

    def test_unknown_scan_returns_404(self):
        """存在しないScanは404になる。"""
        with patch.object(
            app_module,
            "get_scan",
            return_value=None,
        ):
            response = self.client.get("/status/missing-scan")

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()