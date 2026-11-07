import re
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import app
from engine.scoring_v2 import score
from app import _RUNNING
from database import db as db_module
from database import report_store
from database.models import get_scan, init_db
from evidence import store
from report import model as report_model
from verification import consent, ownership
from verification.gate import GateError
from web import auth
from web import csrf
from web import ratelimit

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
        ratelimit.reset()

        from app import app  # noqa: F811 - テスト用に取り直す

        app.config["TESTING"] = True
        self.client = app.test_client()
        auth.reset("test-password")
        with self.client.session_transaction() as sess:
            sess["authenticated"] = True

    def csrf(self):
        """セッションに固定トークンを入れ、送信用の値を返す。"""
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "test-token"
        return "test-token"

    def logout(self):                       # ★ 追加
        """ログアウト状態にする（セッションを空にする）。"""
        with self.client.session_transaction() as sess:
            sess.clear()


    def tearDown(self):
        # 実行中のスレッドが DB を掴み終えるまで待つ。
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
        response = self.client.post("/v2/scan",
                                    data={"target": "  ", "csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 400)


class TestScan(AppTestCase):

    def setUp(self):
        super().setUp()
        patcher = mock.patch("app.service.run_scan", side_effect=fake_run_scan)
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
        data.setdefault("csrf_token", self.csrf())
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
        patcher = mock.patch("app.service.run_scan", side_effect=fake_run_scan)
        patcher.start()
        self.addCleanup(patcher.stop)

    def completed(self):
        response = self.client.post("/v2/scan", data={"target": TARGET,
                                                      "collectors": ["http_headers"],
                                                      "csrf_token": self.csrf()})
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


class TestRunningGuard(AppTestCase):

    def test_claim_rejects_a_live_thread(self):
        gate = threading.Event()
        thread = threading.Thread(target=gate.wait, daemon=True)
        thread.start()
        try:
            app._claim("scan-a", thread)
            with self.assertRaises(app.AlreadyRunning):
                app._claim("scan-a", thread)
        finally:
            gate.set()
            thread.join(timeout=5)
            app._release("scan-a")

    def test_dead_thread_is_replaced(self):
        thread = threading.Thread(target=lambda: None, daemon=True)
        thread.start()
        thread.join(timeout=5)
        try:
            app._claim("scan-b", thread)
            replacement = threading.Thread(target=lambda: None, daemon=True)
            app._claim("scan-b", replacement)
            self.assertIs(_RUNNING["scan-b"], replacement)
        finally:
            app._release("scan-b")

    def test_release_removes_the_entry(self):
        thread = threading.Thread(target=lambda: None, daemon=True)
        app._claim("scan-c", thread)
        app._release("scan-c")
        self.assertNotIn("scan-c", _RUNNING)

    def test_running_is_true_for_a_live_thread(self):
        gate = threading.Event()
        thread = threading.Thread(target=gate.wait, daemon=True)
        thread.start()
        try:
            app._claim("scan-d", thread)
            self.assertTrue(app._running("scan-d"))
        finally:
            gate.set()
            thread.join(timeout=5)
            app._release("scan-d")

    def test_running_is_false_for_a_finished_thread(self):
        thread = threading.Thread(target=lambda: None, daemon=True)
        thread.start()
        thread.join(timeout=5)
        try:
            app._claim("scan-e", thread)
            self.assertFalse(app._running("scan-e"))
        finally:
            app._release("scan-e")


class TestDuplicatePost(AppTestCase):

    def setUp(self):
        super().setUp()
        self.gate = threading.Event()

        def blocking(scan_id, **_kwargs):
            self.gate.wait(timeout=5)
            return fake_run_scan(scan_id)

        patcher = mock.patch("app.service.run_scan", side_effect=blocking)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.gate.set()
        super().tearDown()

    def test_second_post_with_the_same_id_is_409(self):
        token = self.csrf()
        with mock.patch("app.uuid.uuid4", return_value="fixed-id"):
            first = self.client.post("/v2/scan", data={"target": TARGET, "csrf_token": token})
            second = self.client.post("/v2/scan", data={"target": TARGET, "csrf_token": token})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)


class TestCsrf(AppTestCase):

    def setUp(self):
        super().setUp()
        patcher = mock.patch("app.service.run_scan", side_effect=fake_run_scan)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_form_carries_the_token(self):
        self.assertIn(b'name="csrf_token"', self.client.get("/v2/").data)

    def test_post_without_token_is_rejected(self):
        response = self.client.post("/v2/scan", data={"target": TARGET})
        self.assertEqual(response.status_code, 400)

    def test_post_with_wrong_token_is_rejected(self):
        self.csrf()
        response = self.client.post("/v2/scan",
                                    data={"target": TARGET, "csrf_token": "nope"})
        self.assertEqual(response.status_code, 400)

    def test_header_token_is_accepted(self):
        token = self.csrf()
        response = self.client.post("/v2/scan", data={"target": TARGET},
                                    headers={"X-CSRF-Token": token})
        self.assertEqual(response.status_code, 200)


class TestRateLimit(AppTestCase):

    def setUp(self):
        super().setUp()
        patcher = mock.patch("app.service.run_scan", side_effect=fake_run_scan)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_sixth_post_for_the_same_host_is_429(self):
        token = self.csrf()
        codes = [
            self.client.post("/v2/scan",
                             data={"target": TARGET, "csrf_token": token}).status_code
            for _ in range(6)
        ]
        self.assertEqual(codes[:5], [200] * 5)
        self.assertEqual(codes[5], 429)

    def test_other_host_is_not_limited(self):
        token = self.csrf()
        for _ in range(5):
            self.client.post("/v2/scan", data={"target": TARGET, "csrf_token": token})
        response = self.client.post("/v2/scan",
                                    data={"target": "https://other.test/", "csrf_token": token})
        self.assertEqual(response.status_code, 200)

class TestBootstrap(AppTestCase):

    def test_bootstrap_purges_expired_reports(self):
        with mock.patch("app.report_store.purge_expired") as purge:
            app._bootstrap()
        purge.assert_called_once()

    def test_bootstrap_creates_the_job_table(self):
        with mock.patch("app.queue_module.init_queue") as init:
            app._bootstrap()
        init.assert_called_once()


class TestLogin(AppTestCase):

    def test_form_requires_login(self):
        self.logout()
        response = self.client.get("/v2/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/v2/login", response.headers["Location"])

    def test_login_page_is_served(self):
        self.logout()
        response = self.client.get("/v2/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="password"', response.data)

    def test_wrong_password_is_rejected(self):
        self.logout()
        response = self.client.post("/v2/login",
                                    data={"password": "nope", "csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 401)

    def test_correct_password_opens_the_form(self):
        self.logout()
        token = self.csrf()
        response = self.client.post("/v2/login",
                                    data={"password": "test-password", "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/v2/").status_code, 200)

    def test_logout_closes_the_session(self):
        response = self.client.post("/v2/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/v2/").status_code, 302)



if __name__ == "__main__":
    unittest.main()