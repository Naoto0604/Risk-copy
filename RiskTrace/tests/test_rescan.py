import unittest
from unittest.mock import patch

import app as app_module


class TestRescanOptions(unittest.TestCase):

    def setUp(self):
        self.client = app_module.app.test_client()

    def _previous_scan(
        self,
        checks_options,
        analysis_options,
    ):
        return {
            "id": "previous-scan",
            "target_url": "http://127.0.0.1:5000/",
            "protocol": "http",
            "status": "COMPLETED",
            "checks_options": checks_options,
            "analysis_options": analysis_options,
        }

    def test_rescan_preserves_ports_option(self):
        """前回選択したportsを再診断でも引き継ぐ。"""
        previous_scan = self._previous_scan(
            '["https", "headers", "ports"]',
            '["score"]',
        )

        with (
            patch.object(
                app_module,
                "get_scan",
                return_value=previous_scan,
            ),
            patch.object(app_module, "create_scan") as create_scan,
            patch.object(
                app_module.threading,
                "Thread",
            ) as thread_class,
            patch.object(
                app_module,
                "render_template",
                return_value="scanning-page",
            ),
        ):
            response = self.client.post("/rescan/previous-scan")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "scanning-page")

        saved_options = create_scan.call_args.kwargs

        self.assertEqual(
            saved_options["checks_options"],
            {"https", "headers", "ports"},
        )
        self.assertEqual(
            saved_options["analysis_options"],
            {"score"},
        )
        thread_class.assert_called_once()

    def test_rescan_preserves_empty_analysis_options(self):
        """分析機能が空なら、再診断でも空のままにする。"""
        previous_scan = self._previous_scan(
            '["https", "headers"]',
            "[]",
        )

        with (
            patch.object(
                app_module,
                "get_scan",
                return_value=previous_scan,
            ),
            patch.object(app_module, "create_scan") as create_scan,
            patch.object(app_module.threading, "Thread"),
            patch.object(
                app_module,
                "render_template",
                return_value="scanning-page",
            ),
        ):
            response = self.client.post("/rescan/previous-scan")

        self.assertEqual(response.status_code, 200)

        saved_options = create_scan.call_args.kwargs

        self.assertEqual(
            saved_options["analysis_options"],
            set(),
        )
        self.assertEqual(
            saved_options["checks_options"],
            {"https", "headers"},
        )

    def test_missing_scan_returns_404(self):
        """比較元Scanがなければ404を返す。"""
        with patch.object(
            app_module,
            "get_scan",
            return_value=None,
        ):
            response = self.client.post("/rescan/missing-scan")

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()