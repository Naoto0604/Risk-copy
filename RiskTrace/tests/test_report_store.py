import tempfile
import unittest
from pathlib import Path

from analyzer.scoring_v2 import score
from database import db as db_module
from database import report_store
from database.models import init_db
from engine.rule_runner import Finding
from report import model

URL = "https://example.test/"


def finding(rule_id="r", severity="HIGH", evidence=("ev_1",)):
    return Finding(
        id="fnd_1", rule_id=rule_id, title="title", severity=severity,
        confidence="high", subject=URL, message="m", why="w", fix="f", verify="v",
        evidence_ids=evidence,
    )


class StoreTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False

        init_db()
        report_store.init_reports()
        self.scan("scan-1")

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def scan(self, scan_id):
        conn = db_module.get_connection()
        try:
            conn.execute(
                "INSERT INTO scans (id, target_url, protocol, status) VALUES (?, ?, ?, ?)",
                (scan_id, URL, "https", "QUEUED"),
            )
            conn.commit()
        finally:
            conn.close()

    def save(self, scan_id="scan-1", findings=()):
        report = model.build(URL, findings=findings, score_result=score(list(findings)))
        report_store.save_report(scan_id, report, findings=tuple(findings))
        return report


class TestSave(StoreTestCase):

    def test_report_is_stored(self):
        self.save()
        self.assertIsNotNone(report_store.load_report("scan-1"))

    def test_payload_round_trips(self):
        self.save(findings=[finding()])
        stored = report_store.load_report("scan-1")
        self.assertEqual(stored["target"], URL)
        self.assertEqual(stored["groups"][0]["rule_id"], "r")

    def test_findings_are_stored(self):
        self.save(findings=[finding()])
        rows = report_store.findings_for("scan-1")
        self.assertEqual(rows[0]["evidence_ids"], ["ev_1"])

    def test_resaving_replaces_findings(self):
        self.save(findings=[finding(rule_id="a")])
        self.save(findings=[finding(rule_id="b")])
        rows = report_store.findings_for("scan-1")
        self.assertEqual([row["rule_id"] for row in rows], ["b"])

    def test_blank_scan_id_is_rejected(self):
        with self.assertRaises(report_store.ReportStoreError):
            report_store.save_report(" ", model.build(URL, score_result=score([])))


class TestLoad(StoreTestCase):

    def test_unknown_scan_returns_none(self):
        self.assertIsNone(report_store.load_report("nope"))


class TestPrevious(StoreTestCase):

    def test_previous_is_none_without_history(self):
        self.assertIsNone(report_store.previous_for(URL, exclude_scan_id="scan-1"))

    def test_previous_is_returned(self):
        self.save(findings=[finding()])
        previous = report_store.previous_for(URL, exclude_scan_id="scan-2")
        self.assertIn("overall", previous)

    def test_previous_excludes_the_current_scan(self):
        self.save()
        self.assertIsNone(report_store.previous_for(URL, exclude_scan_id="scan-1"))


if __name__ == "__main__":
    unittest.main()