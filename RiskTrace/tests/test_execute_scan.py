import unittest
from unittest.mock import patch

import app as app_module


class TestExecuteScanFailure(unittest.TestCase):

    def test_unexpected_exception_marks_scan_as_failed(self):
        """予期しない例外が発生したら診断をFAILEDにする。"""

        internal_detail = "テスト用の内部エラー詳細"

        with (
            patch.object(
                app_module,
                "crawl",
                side_effect=RuntimeError(internal_detail),
            ),
            patch.object(
                app_module,
                "update_scan_status",
            ) as mock_update_status,
        ):
            app_module.execute_scan(
                scan_id="test-scan",
                url="http://example.com",
                protocol="http",
            )

        mock_update_status.assert_called_once()

        saved_data = mock_update_status.call_args.kwargs

        self.assertEqual(saved_data["scan_id"], "test-scan")
        self.assertEqual(saved_data["status"], "FAILED")
        self.assertIn("RuntimeError", saved_data["error_message"])
        self.assertIn(
            "サーバー側のコンソールを確認してください",
            saved_data["error_message"],
        )

        # 内部のエラー詳細がブラウザ向けのメッセージに
        # 混入していないことも確認する
        self.assertNotIn(
            internal_detail,
            saved_data["error_message"],
        )


if __name__ == "__main__":
    unittest.main()