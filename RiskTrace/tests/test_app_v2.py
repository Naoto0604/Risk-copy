import re
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from analyzer.scoring_v2 import score
from database import db as db_module
from database import report_store
from app_v2 import _RUNNING
from database.models import get_scan, init_db
from evidence import store
from report import model as report_model
from verification import consent, ownership
from verification.gate import GateError

TARGET = "https://example.test/"


def scan_id_of(response):
    """診断中ページの埋め込み scan_id を取り出す。"""
    match = re.search(rb'scanId = "([^"]+)"', response.data)
    if match is None:
        raise AssertionError("scan_id がページにありません")
    return match.group(1).decode("utf-8")


def fake_run_scan(scan_id, *, consent_id=None, allowed=None, **_kwargs):
    """ネットワークに出ない run_scan。"""
    if consent_id == "nope":
        raise GateError(["同意記録が見つかりません"])

    result = score([])
    report = report_model.build(TARGET, score_result=result)
    report_store.save_report(scan_id, report)
    return SimpleNamespace(report=report, status="COMPLETED", score=result,
                           plan_result=None, job_id="job_fake")


class AppTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False

        init_db()
        store.init_evidence()
        report_store.init_reports()
        consent.init_consents()
        ownership.init_proofs()

        from app_v2 import app  # noqa: F811 - テスト用に取り直す

        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self): 
        # 実行中のスレッドが DB を触り終えるまで待つ。
        deadline = time.time() + 5
        while time.time() < deadline:
            if not _RUNNING:
                break
            time.sleep(0.02)

        for thread in list(_RUNNING.values()):
            thread.join(timeout=5)

        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal

        for _ in range(20):
            try:
                self._tmp.cleanup()
                break
            except PermissionError:
                time.sleep(0.05)

class TestForm(AppTestCase):

    def test_form_is_served(self):
        response = self.client.get("/v2/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data, "本文が空です")
        self.assertIn("低侵襲アクティブ診断".encode("utf-8"), response.data)

    def test_collectors_are_listed(self):
        response = self.client.get("/v2/")
        self.assertIn(b'name="collectors"', response.data)

    def test_blank_target_is_rejected(self):
        response = self.client.post("/v2/scan", data={"target": "  "})
        self.assertEqual(response.status_code, 400)


class TestScan(AppTestCase):

    def setUp(self):
        super().setUp()
        patcher = mock.patch("app_v2.service.run_scan", side_effect=fake_run_scan)
        patcher.start()
        self.addCleanup(patcher.stop)

    def wait(self, scan_id, limit=100):
        for _ in range(limit):
            row = get_scan(scan_id)
            if row is not None and row["status"] in ("COMPLETED", "FAILED"):
                return row
            time.sleep(0.02)
        return get_scan(scan_id)

    def post(self, **data):
        return self.client.post("/v2/scan", data=data)

    def test_post_returns_the_scanning_page(self):
        response = self.post(target=TARGET, collectors=["http_headers"])
        self.assertEqual(response.status_code, 200)
        self.assertIn("診断中".encode("utf-8"), response.data)

    def test_completed_scan_reaches_a_report(self):
        response = self.post(target=TARGET, collectors=["http_headers"])
        scan_id = scan_id_of(response)
        self.assertEqual(self.wait(scan_id)["status"], "COMPLETED")
        self.assertEqual(self.client.get(f"/v2/report/{scan_id}").status_code, 200)

    def test_missing_consent_ends_as_failed(self):
        response = self.post(target=TARGET, consent_id="nope", collectors=["http_headers"])
        scan_id = scan_id_of(response)
        row = self.wait(scan_id)
        self.assertEqual(row["status"], "FAILED")
        self.assertIn("同意記録が見つかりません", row["error_message"])

    def test_status_endpoint_reports_the_state(self):
        response = self.post(target=TARGET, collectors=["http_headers"])
        scan_id = scan_id_of(response)
        payload = self.client.get(f"/v2/status/{scan_id}").get_json()
        self.assertIn(payload["status"], ("QUEUED", "RUNNING", "COMPLETED", "FAILED"))
        self.assertIn("running", payload)

    def test_status_of_unknown_scan_is_404(self):
        self.assertEqual(self.client.get("/v2/status/nope").status_code, 404)


class TestReport(AppTestCase):

    def setUp(self):
        super().setUp()
        patcher = mock.patch("app_v2.service.run_scan", side_effect=fake_run_scan)
        patcher.start()
        self.addCleanup(patcher.stop)

    def completed(self):
        response = self.client.post("/v2/scan", data={"target": TARGET,
                                                      "collectors": ["http_headers"]})
        scan_id = scan_id_of(response)
        for _ in range(100):
            if get_scan(scan_id)["status"] == "COMPLETED":
                return scan_id
            time.sleep(0.02)
        raise AssertionError("完了しませんでした")

    def test_unknown_scan_is_404(self):
        self.assertEqual(self.client.get("/v2/report/nope").status_code, 404)

    def test_json_export_is_served(self):
        scan_id = self.completed()
        response = self.client.get(f"/v2/report/{scan_id}/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_csv_export_is_served(self):
        scan_id = self.completed()
        response = self.client.get(f"/v2/report/{scan_id}/csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["Content-Type"])

    def test_filename_is_sanitised(self):
        scan_id = self.completed()
        response = self.client.get(f"/v2/report/{scan_id}/json")
        self.assertIn("risktrace-example.test-", response.headers["Content-Disposition"])

    def test_export_of_unknown_scan_is_404(self):
        self.assertEqual(self.client.get("/v2/report/nope/csv").status_code, 404)

if __name__ == "__main__":
    unittest.main()