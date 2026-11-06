import csv
import io
import json
import unittest

from report_export import build_csv_bytes, build_json_bytes


class TestSubtypeExport(unittest.TestCase):

    def setUp(self):
        self.scan = {
            "id": "test-scan",
            "target_url": "https://example.test/",
            "protocol": "https",
            "status": "COMPLETED",
            "created_at": "2026-10-27 12:00:00",
            "analysis_options": '["score"]',
            "checks_options": '["headers"]',
        }

        self.finding = {
            "id": 1,
            "scan_id": "test-scan",
            "type": "SECURITY_HEADER",
            "subtype": "Strict-Transport-Security",
            "severity": "MEDIUM",
            "title": "HSTSが設定されていません",
            "url": "https://example.test/",
            "description": "HSTSヘッダーがありません。",
            "evidence": "テスト用Evidence",
            "recommendation": "HSTSの設定を確認してください。",
        }

    def test_json_export_preserves_subtype(self):
        """JSON出力でsubtypeが保持される。"""
        output = build_json_bytes(
            self.scan,
            [self.finding],
        )

        payload = json.loads(output.decode("utf-8"))

        self.assertEqual(
            payload["findings"][0]["subtype"],
            "Strict-Transport-Security",
        )

    def test_csv_export_preserves_subtype(self):
        """CSV出力でsubtypeが保持される。"""
        output = build_csv_bytes(
            self.scan,
            [self.finding],
        )

        text = output.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text)))

        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["subtype"],
            "Strict-Transport-Security",
        )


if __name__ == "__main__":
    unittest.main()