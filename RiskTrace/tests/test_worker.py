import tempfile
import threading
import time
import unittest
from pathlib import Path
from engine import worker as worker_module
from database import db as db_module
from database import queue
from engine.scheduler import Budgets
from engine.worker import RunResult, Worker


class WorkerTestCase(unittest.TestCase):

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
        self._threads = []

    def tearDown(self):
        for worker, _thread in self._threads:
            worker.stop()
        for _worker, thread in self._threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "Worker スレッドが停止しませんでした")

        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def start(self, worker, poll_interval=0.01):
        thread = threading.Thread(
            target=worker.run_forever, args=(poll_interval,), daemon=True
        )
        self._threads.append((worker, thread))
        thread.start()
        return thread

    def enqueue(self, **kwargs):
        self._seq += 1
        scan_id = f"scan-{self._seq}"
        conn = db_module.get_connection()
        try:
            conn.execute(
                "INSERT INTO scans (id, target_url, protocol, status) VALUES (?, ?, ?, ?)",
                (scan_id, "https://example.test/", "https", "QUEUED"),
            )
            conn.commit()
        finally:
            conn.close()
        return queue.enqueue(scan_id, **kwargs)

    def worker(self, runner, **kwargs):
        kwargs.setdefault("lease_seconds", 30)
        kwargs.setdefault("heartbeat_interval", 0.05)
        kwargs.setdefault("budgets", Budgets(seconds=60, per_host_interval=0.001))
        return Worker(runner, **kwargs)


class TestProcessing(WorkerTestCase):

    def test_completes_a_job(self):
        job_id = self.enqueue()
        seen = []

        def runner(job, scheduler):
            seen.append(job.id)
            return None

        self.assertEqual(self.worker(runner).run_once(), queue.COMPLETED)
        self.assertEqual(seen, [job_id])
        self.assertEqual(queue.get_job(job_id).status, queue.COMPLETED)

    def test_runner_receives_job_and_scheduler(self):
        self.enqueue()
        received = {}

        def runner(job, scheduler):
            received["job"] = job
            received["scheduler"] = scheduler

        self.worker(runner).run_once()
        self.assertEqual(received["job"].scan_id, "scan-1")
        self.assertIsNotNone(received["scheduler"])

    def test_runner_can_report_partial(self):
        job_id = self.enqueue()
        result = self.worker(lambda j, s: RunResult(queue.PARTIAL, "WAF ブロック")).run_once()
        self.assertEqual(result, queue.PARTIAL)
        self.assertEqual(queue.get_job(job_id).last_error, "WAF ブロック")

    def test_run_once_returns_none_when_empty(self):
        self.assertIsNone(self.worker(lambda j, s: None).run_once())

    def test_non_callable_runner_is_rejected(self):
        with self.assertRaises(TypeError):
            Worker("not callable")

    def test_short_lease_is_rejected(self):
        with self.assertRaises(ValueError):
            Worker(lambda j, s: None, lease_seconds=1)

    def test_runner_result_status_is_validated(self):
        with self.assertRaises(ValueError):
            RunResult(queue.FAILED)


class TestFailureMapping(WorkerTestCase):

    def test_unexpected_exception_marks_failed(self):
        job_id = self.enqueue()

        def runner(job, scheduler):
            raise RuntimeError("内部エラー")

        self.assertEqual(self.worker(runner).run_once(), queue.FAILED)
        job = queue.get_job(job_id)
        self.assertEqual(job.status, queue.FAILED)
        self.assertIn("RuntimeError", job.last_error)

    def test_budget_exhaustion_marks_partial(self):
        job_id = self.enqueue()

        def runner(job, scheduler):
            scheduler.reserve()
            scheduler.reserve()

        worker = self.worker(runner, budgets=Budgets(requests=1, seconds=60))
        self.assertEqual(worker.run_once(), queue.PARTIAL)
        self.assertIn("予算切れ", queue.get_job(job_id).last_error)

    def test_scheduler_cancellation_marks_partial(self):
        """Worker 側の中断要求は RUNNING のままなので finish で PARTIAL になる。"""
        job_id = self.enqueue()

        def runner(job, scheduler):
            scheduler.cancel("テスト中断")
            scheduler.check_cancel()

        self.assertEqual(self.worker(runner).run_once(), queue.PARTIAL)
        self.assertIn("中断", queue.get_job(job_id).last_error)

    def test_runner_error_is_logged(self):
        self.enqueue()

        def runner(job, scheduler):
            raise RuntimeError("x")

        worker = self.worker(runner)
        worker.run_once()
        events = [entry["event"] for entry in worker.log()]
        self.assertIn("runner_error", events)


class TestCancellationFromDb(WorkerTestCase):
    """DB 側で CANCELLED にされた場合。状態は CANCELLED のまま維持する。"""

    def run_until_cancelled(self, reason=None):
        job_id = self.enqueue()

        def runner(job, scheduler):
            for _ in range(300):
                scheduler.check_cancel()
                time.sleep(0.01)

        def cancel_soon():
            time.sleep(0.1)
            queue.cancel(job_id, reason=reason)

        threading.Thread(target=cancel_soon, daemon=True).start()
        worker = self.worker(runner)
        return job_id, worker, worker.run_once()

    def test_result_is_cancelled(self):
        _job_id, _worker, result = self.run_until_cancelled()
        self.assertEqual(result, queue.CANCELLED)

    def test_status_stays_cancelled(self):
        job_id, _worker, _result = self.run_until_cancelled(reason="外部から")
        job = queue.get_job(job_id)
        self.assertEqual(job.status, queue.CANCELLED)
        self.assertEqual(job.last_error, "外部から")

    def test_finish_is_skipped(self):
        _job_id, worker, _result = self.run_until_cancelled()
        entries = [e for e in worker.log() if e["event"] == "skip_finish"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["reason"], "cancelled")

    def test_cancel_is_not_reported_as_lease_loss(self):
        _job_id, worker, _result = self.run_until_cancelled()
        events = [entry["event"] for entry in worker.log()]
        self.assertIn("job_cancelled", events)
        self.assertNotIn("lease_lost", events)
        
    def test_cancel_during_heartbeat_is_not_lease_loss(self):
        """状態を読んだ直後に cancel され、heartbeat が失敗する競合を固定する。"""
        job_id = self.enqueue()
        original = worker_module.queue.heartbeat

        def racy_heartbeat(target, worker_id, *, lease_seconds):
            queue.cancel(target, reason="外部から")
            return False

        worker_module.queue.heartbeat = racy_heartbeat

        def runner(job, scheduler):
            for _ in range(300):
                scheduler.check_cancel()
                time.sleep(0.01)

        try:
            worker = self.worker(runner)
            result = worker.run_once()
        finally:
            worker_module.queue.heartbeat = original

        self.assertEqual(result, queue.CANCELLED)
        events = [entry["event"] for entry in worker.log()]
        self.assertIn("job_cancelled", events)
        self.assertNotIn("lease_lost", events)

class TestHeartbeat(WorkerTestCase):

    def test_heartbeat_updates_the_lease_during_the_run(self):
        job_id = self.enqueue()

        def runner(job, scheduler):
            time.sleep(0.3)

        self.worker(runner, lease_seconds=4, heartbeat_interval=0.05).run_once()
        job = queue.get_job(job_id)
        self.assertIsNotNone(job.heartbeat_at)
        self.assertGreater(job.heartbeat_at, job.started_at)

    def test_lease_loss_skips_finish(self):
        job_id = self.enqueue()

        def runner(job, scheduler):
            conn = db_module.get_connection()
            try:
                conn.execute(
                    "UPDATE jobs SET status = 'QUEUED', worker_id = NULL, lease_expires_at = NULL"
                    " WHERE id = ?",
                    (job_id,),
                )
                conn.commit()
            finally:
                conn.close()
            time.sleep(0.2)

        worker = self.worker(runner, lease_seconds=30, heartbeat_interval=0.05)
        result = worker.process(queue.claim_next("w0", lease_seconds=30))

        self.assertEqual(result, queue.RUNNING)
        entries = [e for e in worker.log() if e["event"] == "skip_finish"]
        self.assertEqual(entries[0]["reason"], "lease_lost")


class TestLifecycle(WorkerTestCase):

    def test_stop_exits_the_loop(self):
        worker = self.worker(lambda j, s: None)
        thread = self.start(worker)
        time.sleep(0.05)
        worker.stop()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_worker_is_registered_while_running(self):
        worker = self.worker(lambda j, s: None)
        thread = self.start(worker)
        time.sleep(0.05)

        info = queue.get_worker(worker.worker_id)
        self.assertIsNotNone(info)
        self.assertIn(info["status"], ("idle", "running"))

        worker.stop()
        thread.join(timeout=3)
        self.assertEqual(queue.get_worker(worker.worker_id)["status"], "stopped")

    def test_run_forever_processes_queued_jobs(self):
        job_id = self.enqueue()
        worker = self.worker(lambda j, s: None)
        self.start(worker)

        for _ in range(150):
            if queue.get_job(job_id).status == queue.COMPLETED:
                break
            time.sleep(0.02)

        self.assertEqual(queue.get_job(job_id).status, queue.COMPLETED)

    def test_zero_poll_interval_is_rejected(self):
        with self.assertRaises(ValueError):
            self.worker(lambda j, s: None).run_forever(0)


if __name__ == "__main__":
    unittest.main()