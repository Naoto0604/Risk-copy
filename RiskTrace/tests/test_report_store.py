import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from engine.scoring_v2 import score
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

    def save(self, scan_id="scan-1", findings=(), target=URL):
        report = model.build(target, findings=findings, score_result=score(list(findings)))
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

    def test_other_scheme_matches(self):
        self.scan("scan-2")
        self.save("scan-1")
        previous = report_store.previous_for("http://example.test", exclude_scan_id="scan-2")
        self.assertEqual(previous["scan_id"], "scan-1")

    def test_trailing_slash_is_ignored(self):
        self.scan("scan-2")
        self.save("scan-1", target="https://example.test")
        self.assertIsNotNone(
            report_store.previous_for("https://example.test/", exclude_scan_id="scan-2")
        )

    def test_case_is_ignored(self):
        self.scan("scan-2")
        self.save("scan-1", target="https://Example.Test/")
        self.assertIsNotNone(
            report_store.previous_for("https://example.test/", exclude_scan_id="scan-2")
        )

    def test_different_host_does_not_match(self):
        self.scan("scan-2")
        self.save("scan-1")
        self.assertIsNone(
            report_store.previous_for("https://other.test/", exclude_scan_id="scan-2")
        )

    def test_blank_target_returns_none(self):
        self.save()
        self.assertIsNone(report_store.previous_for("  ", exclude_scan_id="scan-2"))

    def test_tiebreak_prefers_the_larger_scan_id(self):
        self.scan("scan-2")
        self.scan("scan-3")
        self.save("scan-1")
        self.save("scan-3")
        conn = db_module.get_connection()
        try:
            conn.execute("UPDATE reports_v2 SET created_at = '2026-01-01T00:00:00+00:00'")
            conn.commit()
        finally:
            conn.close()

        previous = report_store.previous_for(URL, exclude_scan_id="scan-2")
        self.assertEqual(previous["scan_id"], "scan-3")

    def test_compared_on_is_recorded(self):
        self.save()
        previous = report_store.previous_for(URL, exclude_scan_id="scan-2")
        self.assertEqual(previous["compared_on"], "host")


class TestHostMigration(StoreTestCase):

    def test_old_table_gains_the_host_column(self):
        conn = db_module.get_connection()
        try:
            conn.execute("DROP TABLE reports_v2")
            conn.execute(
                "CREATE TABLE reports_v2 (scan_id TEXT PRIMARY KEY, target TEXT NOT NULL,"
                " overall INTEGER NOT NULL, level TEXT NOT NULL, coverage REAL,"
                " payload TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO reports_v2 VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("scan-1", URL, 10, "LOW", 1.0, "{}", "2026-01-01T00:00:00+00:00"),
            )
            conn.commit()
        finally:
            conn.close()

        report_store.init_reports()

        conn = db_module.get_connection()
        try:
            row = conn.execute(
                "SELECT host FROM reports_v2 WHERE scan_id = 'scan-1'"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["host"], "example.test")

class TestPurge(StoreTestCase):

    def age(self, scan_id, created_at):
        conn = db_module.get_connection()
        try:
            conn.execute(
                "UPDATE reports_v2 SET created_at = ? WHERE scan_id = ?",
                (created_at, scan_id),
            )
            conn.commit()
        finally:
            conn.close()

    def test_old_report_is_removed(self):
        self.save()
        self.age("scan-1", "2020-01-01T00:00:00+00:00")
        self.assertEqual(report_store.purge_expired(), 1)
        self.assertIsNone(report_store.load_report("scan-1"))

    def test_new_report_is_kept(self):
        self.save()
        self.assertEqual(report_store.purge_expired(), 0)
        self.assertIsNotNone(report_store.load_report("scan-1"))

    def test_findings_are_removed_too(self):
        self.save(findings=[finding()])
        self.age("scan-1", "2020-01-01T00:00:00+00:00")
        report_store.purge_expired()
        self.assertEqual(report_store.findings_for("scan-1"), [])

    def test_retention_can_be_shortened(self):
        self.save()
        self.age("scan-1", "2026-01-01T00:00:00+00:00")
        now = datetime(2026, 2, 1, tzinfo=timezone.utc)
        self.assertEqual(report_store.purge_expired(now=now, retention_days=7), 1)

    def test_invalid_retention_is_rejected(self):
        with self.assertRaises(report_store.ReportStoreError):
            report_store.purge_expired(retention_days=0)



if __name__ == "__main__":
    unittest.main()