import csv
import io
import json
import unittest

from engine.legacy_export import (
    build_csv_bytes,
    build_export_payload,
    build_json_bytes,
    register_export_routes,
)

try:
    from flask import Flask
except ImportError:  # Helper tests can still run without Flask installed.
    Flask = None


SAMPLE_SCAN = {
    "id": "scan-123",
    "target_url": "https://example.test/",
    "protocol": "https",
    "status": "COMPLETED",
    "created_at": "2026-10-27 12:00:00",
    "analysis_options": '["score", "priority"]',
    "checks_options": '["https", "ports"]',
}

SAMPLE_FINDINGS = [
    {
        "id": 10,
        "scan_id": "scan-123",
        "type": "TLS",
        "subtype": "TLS_CERTIFICATE_VERIFICATION_FAILED",
        "severity": "MEDIUM",
        "title": "証明書の検証に失敗しました",
        "url": "https://example.test/",
        "description": "自己署名証明書です",
        "evidence": "TLS certificate verification: FAILED",
        "recommendation": "証明書チェーンを確認してください",
    }
]


class TestReportExportHelpers(unittest.TestCase):

    def test_json_export_preserves_japanese(self):
        payload = json.loads(build_json_bytes(SAMPLE_SCAN, SAMPLE_FINDINGS).decode("utf-8"))

        self.assertEqual(payload["target"], SAMPLE_SCAN["target_url"])
        self.assertEqual(payload["groups"][0]["severity"], "MEDIUM")
        self.assertEqual(payload["groups"][0]["count"], 1)
        self.assertIn("証明書", payload["groups"][0]["title"])

    def test_json_export_contains_schema_version(self):
        payload = build_export_payload(
            SAMPLE_SCAN, SAMPLE_FINDINGS, exported_at="2026-10-27T00:00:00+00:00"
        )
        self.assertEqual(payload["schema_version"], "2.0")
        self.assertEqual(payload["generated_at"], "2026-10-27T00:00:00+00:00")

    def test_csv_export_has_one_row_per_group(self):
        content = build_csv_bytes(SAMPLE_SCAN, SAMPLE_FINDINGS).decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(content, newline="")))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "MEDIUM")
        self.assertEqual(rows[0]["target"], SAMPLE_SCAN["target_url"])
        self.assertIn("証明書", rows[0]["title"])

    def test_repeated_rule_is_one_row_with_count(self):
        findings = [dict(SAMPLE_FINDINGS[0], id=11), dict(SAMPLE_FINDINGS[0], id=12)]
        payload = json.loads(build_json_bytes(SAMPLE_SCAN, findings).decode("utf-8"))
        csv_content = build_csv_bytes(SAMPLE_SCAN, findings).decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(csv_content, newline="")))

        self.assertEqual(len(payload["groups"]), 1)
        self.assertEqual(payload["groups"][0]["count"], 2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], "2")

    def test_csv_export_mitigates_formula_injection(self):
        findings = [dict(SAMPLE_FINDINGS[0], title='=HYPERLINK("https://bad.example")')]
        content = build_csv_bytes(SAMPLE_SCAN, findings).decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(content, newline="")))

        self.assertTrue(rows[0]["title"].startswith("'="))

    def test_csv_export_is_excel_friendly_utf8_with_bom(self):
        content = build_csv_bytes(SAMPLE_SCAN, SAMPLE_FINDINGS)
        self.assertTrue(content.startswith(b"\xef\xbb\xbf"))

    def test_missing_scan_is_rejected_by_payload_builder(self):
        with self.assertRaises(ValueError):
            build_export_payload(None, [])

    def test_empty_findings_still_exports_header(self):
        content = build_csv_bytes(SAMPLE_SCAN, []).decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(content, newline="")))

        self.assertEqual(len(rows), 1)
        self.assertIn("rule_id", rows[0])


@unittest.skipIf(Flask is None, "Flask is required for route integration tests")
class TestReportExportRoutes(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        register_export_routes(
            self.app,
            get_scan=lambda scan_id: SAMPLE_SCAN if scan_id == "scan-123" else None,
            get_findings=lambda scan_id: SAMPLE_FINDINGS,
        )
        self.client = self.app.test_client()

    def test_json_route_downloads_completed_scan(self):
        response = self.client.get("/export/scan-123/json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.content_type)
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertEqual(json.loads(response.data)["groups"][0]["count"], 1)

    def test_csv_route_downloads_completed_scan(self):
        response = self.client.get("/export/scan-123/csv")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn(".csv", response.headers["Content-Disposition"])

    def test_unknown_scan_returns_404(self):
        self.assertEqual(self.client.get("/export/unknown/json").status_code, 404)

    def test_unsupported_format_returns_404(self):
        self.assertEqual(self.client.get("/export/scan-123/xml").status_code, 404)

    def test_incomplete_scan_returns_409(self):
        app = Flask("incomplete-test")
        app.config["TESTING"] = True
        incomplete = dict(SAMPLE_SCAN, status="RUNNING")
        register_export_routes(
            app,
            get_scan=lambda scan_id: incomplete,
            get_findings=lambda scan_id: [],
        )

        self.assertEqual(app.test_client().get("/export/scan-123/json").status_code, 409)


if __name__ == "__main__":
    unittest.main()