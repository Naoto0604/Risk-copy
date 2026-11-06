import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database import db as db_module
from database import queue


class QueueTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False

        conn = db_module.get_connection()
        try:
            conn.execute("""
                CREATE TABLE scans (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    protocol TEXT,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    analysis_options TEXT NOT NULL DEFAULT '[]',
                    checks_options TEXT NOT NULL DEFAULT '[]'
                )
            """)
            conn.commit()
        finally:
            conn.close()

        queue.init_queue()
        self._seq = 0

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def make_scan(self, scan_id="scan-1"):
        conn = db_module.get_connection()
        try:
            conn.execute(
                "INSERT INTO scans (id, target_url, protocol, status) VALUES (?, ?, ?, ?)",
                (scan_id, "https://example.test/", "https", "QUEUED"),
            )
            conn.commit()
        finally:
            conn.close()
        return scan_id

    def enqueue(self, **kwargs):
        self._seq += 1
        return queue.enqueue(self.make_scan(f"scan-{self._seq}"), **kwargs)


class TestEnqueue(QueueTestCase):

    def test_job_starts_queued(self):
        job = queue.get_job(self.enqueue())
        self.assertEqual(job.status, queue.QUEUED)
        self.assertEqual(job.attempts, 0)
        self.assertIsNone(job.worker_id)
        self.assertIsNone(job.run_token)

    def test_explicit_job_id_is_used(self):
        self.assertEqual(self.enqueue(job_id="job_fixed"), "job_fixed")

    def test_duplicate_job_id_is_rejected(self):
        self.enqueue(job_id="job_fixed")
        with self.assertRaises(queue.QueueError):
            self.enqueue(job_id="job_fixed")

    def test_blank_scan_id_is_rejected(self):
        with self.assertRaises(queue.QueueError):
            queue.enqueue("  ")

    def test_max_attempts_below_one_is_rejected(self):
        with self.assertRaises(queue.QueueError):
            queue.enqueue(self.make_scan(), max_attempts=0)

    def test_unknown_status_cannot_be_stored(self):
        with self.assertRaises(sqlite3.IntegrityError):
            conn = db_module.get_connection()
            try:
                conn.execute(
                    "INSERT INTO jobs (id, scan_id, status, created_at) VALUES (?, ?, ?, ?)",
                    ("job_x", self.make_scan("scan-x"), "DONE", "2026-01-01T00:00:00+00:00"),
                )
            finally:
                conn.close()

    def test_scan_delete_cascades(self):
        scan_id = self.make_scan("scan-del")
        queue.enqueue(scan_id)
        conn = db_module.get_connection()
        try:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(queue.list_jobs(), [])


class TestClaim(QueueTestCase):

    def test_claim_marks_running_and_issues_run_token(self):
        job_id = self.enqueue()
        job = queue.claim_next("w1")
        self.assertEqual(job.id, job_id)
        self.assertEqual(job.status, queue.RUNNING)
        self.assertEqual(job.worker_id, "w1")
        self.assertTrue(job.run_token.startswith("run_"))
        self.assertEqual(job.attempts, 1)

    def test_claim_returns_none_when_empty(self):
        self.assertIsNone(queue.claim_next("w1"))

    def test_same_job_is_not_claimed_twice(self):
        self.enqueue()
        self.assertIsNotNone(queue.claim_next("w1"))
        self.assertIsNone(queue.claim_next("w2"))

    def test_oldest_job_is_claimed_first(self):
        first = self.enqueue()
        second = self.enqueue()
        self.assertEqual(queue.claim_next("w1").id, first)
        self.assertEqual(queue.claim_next("w1").id, second)

    def test_blank_worker_id_is_rejected(self):
        self.enqueue()
        with self.assertRaises(queue.QueueError):
            queue.claim_next("  ")

    def test_each_claim_issues_a_new_run_token(self):
        job_id = self.enqueue()
        first = queue.claim_next("w1").run_token
        queue.finish(job_id, queue.FAILED)
        conn = db_module.get_connection()
        try:
            conn.execute("UPDATE jobs SET status = 'QUEUED' WHERE id = ?", (job_id,))
            conn.commit()
        finally:
            conn.close()
        self.assertNotEqual(queue.claim_next("w2").run_token, first)

    def test_concurrent_claim_never_double_assigns(self):
        expected = {self.enqueue() for _ in range(20)}
        claimed = []
        lock = threading.Lock()

        def worker(name):
            while True:
                job = queue.claim_next(name)
                if job is None:
                    return
                with lock:
                    claimed.append(job.id)

        threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(claimed), 20)
        self.assertEqual(len(set(claimed)), 20)
        self.assertEqual(set(claimed), expected)


class TestHeartbeat(QueueTestCase):

    def test_heartbeat_extends_lease(self):
        job_id = self.enqueue()
        queue.claim_next("w1", lease_seconds=1)
        self.assertTrue(queue.heartbeat(job_id, "w1", lease_seconds=600))
        job = queue.get_job(job_id)
        self.assertGreater(job.lease_expires_at, job.heartbeat_at)

    def test_heartbeat_from_other_worker_fails(self):
        job_id = self.enqueue()
        queue.claim_next("w1")
        self.assertFalse(queue.heartbeat(job_id, "w2"))

    def test_heartbeat_on_queued_job_fails(self):
        job_id = self.enqueue()
        self.assertFalse(queue.heartbeat(job_id, "w1"))


class TestFinish(QueueTestCase):

    def test_finish_sets_terminal_status(self):
        job_id = self.enqueue()
        queue.claim_next("w1")
        queue.finish(job_id, queue.COMPLETED)
        job = queue.get_job(job_id)
        self.assertEqual(job.status, queue.COMPLETED)
        self.assertIsNotNone(job.finished_at)
        self.assertIsNone(job.lease_expires_at)

    def test_partial_and_failed_keep_error_text(self):
        for status in (queue.PARTIAL, queue.FAILED):
            with self.subTest(status=status):
                job_id = self.enqueue()
                queue.claim_next("w1")
                queue.finish(job_id, status, error="WAF ブロック")
                self.assertEqual(queue.get_job(job_id).last_error, "WAF ブロック")

    def test_finish_on_queued_job_is_rejected(self):
        job_id = self.enqueue()
        with self.assertRaises(queue.QueueError):
            queue.finish(job_id, queue.COMPLETED)

    def test_non_terminal_status_is_rejected(self):
        job_id = self.enqueue()
        queue.claim_next("w1")
        with self.assertRaises(queue.QueueError):
            queue.finish(job_id, queue.RUNNING)

    def test_finished_job_cannot_be_claimed(self):
        job_id = self.enqueue()
        queue.claim_next("w1")
        queue.finish(job_id, queue.COMPLETED)
        self.assertIsNone(queue.claim_next("w2"))


class TestPauseResumeCancel(QueueTestCase):

    def test_pause_then_resume_returns_to_queue(self):
        job_id = self.enqueue()
        queue.claim_next("w1")
        queue.pause(job_id, reason="予算待ち")
        self.assertEqual(queue.get_job(job_id).status, queue.PAUSED)
        self.assertTrue(queue.get_job(job_id).can_resume)

        queue.resume(job_id)
        self.assertEqual(queue.get_job(job_id).status, queue.QUEUED)
        self.assertIsNotNone(queue.claim_next("w2"))

    def test_resume_on_queued_job_is_rejected(self):
        with self.assertRaises(queue.QueueError):
            queue.resume(self.enqueue())

    def test_cancel_works_from_queued(self):
        job_id = self.enqueue()
        queue.cancel(job_id, reason="利用者中断")
        self.assertEqual(queue.get_job(job_id).status, queue.CANCELLED)

    def test_cancel_works_from_running(self):
        job_id = self.enqueue()
        queue.claim_next("w1")
        queue.cancel(job_id)
        self.assertTrue(queue.get_job(job_id).is_terminal)

    def test_cancel_twice_is_rejected(self):
        job_id = self.enqueue()
        queue.cancel(job_id)
        with self.assertRaises(queue.QueueError):
            queue.cancel(job_id)


class TestRecovery(QueueTestCase):

    def test_release_stale_requeues_expired_job(self):
        job_id = self.enqueue()
        queue.claim_next("w1", lease_seconds=1)
        future = datetime.now(timezone.utc) + timedelta(seconds=5)

        result = queue.release_stale(now=future)
        self.assertEqual(result, [(job_id, queue.QUEUED)])
        job = queue.get_job(job_id)
        self.assertEqual(job.status, queue.QUEUED)
        self.assertIsNone(job.worker_id)
        self.assertIn("失効", job.last_error)

    def test_release_stale_keeps_live_job(self):
        job_id = self.enqueue()
        queue.claim_next("w1", lease_seconds=600)
        self.assertEqual(queue.release_stale(), [])
        self.assertEqual(queue.get_job(job_id).status, queue.RUNNING)

    def test_release_stale_fails_when_attempts_exhausted(self):
        job_id = self.enqueue(max_attempts=1)
        queue.claim_next("w1", lease_seconds=1)
        future = datetime.now(timezone.utc) + timedelta(seconds=5)

        self.assertEqual(queue.release_stale(now=future), [(job_id, queue.FAILED)])
        self.assertIsNotNone(queue.get_job(job_id).finished_at)

    def test_recovered_job_can_be_claimed_again(self):
        job_id = self.enqueue()
        queue.claim_next("w1", lease_seconds=1)
        queue.release_stale(now=datetime.now(timezone.utc) + timedelta(seconds=5))

        job = queue.claim_next("w2")
        self.assertEqual(job.id, job_id)
        self.assertEqual(job.attempts, 2)

    def test_recover_all_running_ignores_lease(self):
        job_id = self.enqueue()
        queue.claim_next("w1", lease_seconds=600)
        self.assertEqual(queue.recover_all_running(), [(job_id, queue.QUEUED)])


class TestWorkerRegistry(QueueTestCase):

    def test_register_and_touch(self):
        queue.register_worker("w1")
        self.assertEqual(queue.count_active_workers(), 0)
        queue.touch_worker("w1", current_job_id="job_1")
        self.assertEqual(queue.count_active_workers(), 1)
        queue.touch_worker("w1")
        self.assertEqual(queue.count_active_workers(), 0)

    def test_unregister_stops_worker(self):
        queue.register_worker("w1")
        queue.touch_worker("w1", current_job_id="job_1")
        queue.unregister_worker("w1")
        self.assertEqual(queue.count_active_workers(), 0)

    def test_worker_limit_is_enforced(self):
        for index in range(queue.WORKER_LIMIT):
            queue.register_worker(f"w{index}")
            queue.touch_worker(f"w{index}", current_job_id="job_1")
        self.assertFalse(queue.can_start_worker())

    def test_register_is_idempotent(self):
        queue.register_worker("w1")
        queue.register_worker("w1")
        conn = db_module.get_connection()
        try:
            n = conn.execute("SELECT COUNT(*) AS n FROM workers").fetchone()["n"]
        finally:
            conn.close()
        self.assertEqual(n, 1)


class TestIntrospection(QueueTestCase):

    def test_list_jobs_filters_by_status(self):
        a = self.enqueue()
        b = self.enqueue()
        queue.claim_next("w1")
        self.assertEqual([j.id for j in queue.list_jobs(queue.RUNNING)], [a])
        self.assertEqual([j.id for j in queue.list_jobs(queue.QUEUED)], [b])

    def test_count_by_status_covers_all_states(self):
        self.enqueue()
        counts = queue.count_by_status()
        self.assertEqual(set(counts), set(queue.STATUSES))
        self.assertEqual(counts[queue.QUEUED], 1)

    def test_reset_queue_clears_rows(self):
        self.enqueue()
        queue.reset_queue()
        self.assertEqual(queue.list_jobs(), [])


if __name__ == "__main__":
    unittest.main()