import tempfile
import unittest
from pathlib import Path
from verification import consent, ownership
from database import db as db_module
from database import queue
from database import report_store
from engine import plan, service
from engine.observations import Observation
from engine.rules import load_rules_from_text
from evidence import store
from verification.gate import GateError
from verification import scope as scope_module
from verification.ownership import FetchResult


URL = "https://example.test/"


def step(name, result=None):
    def collect(target, scheduler, context):
        return result

    return plan.Step(name, collect)


def ruleset(text):
    return load_rules_from_text(text, "probe.yaml")


HIT_RULE = """
- id: probe.hit
  title: t
  severity: HIGH
  confidence: high
  requires: []
  collectors:
    - a
  when:
    obs:
      collector: a
      key: v
      op: eq
      value: 1
  message: m
  why: w
  fix: f
  verify: v
"""


class ServiceTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False
        store.init_evidence()
        report_store.init_reports()
        consent.init_consents()
        ownership.init_proofs()
        conn = db_module.get_connection()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS scans ("
                " id TEXT PRIMARY KEY, target_url TEXT NOT NULL,"
                " protocol TEXT NOT NULL, status TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO scans (id, target_url, protocol, status) VALUES (?, ?, ?, ?)",
                ("scan-1", URL, "https", "QUEUED"),
            )
            conn.commit()
        finally:
            conn.close()

        queue.init_queue()

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def run_scan(self, **kwargs):
        kwargs.setdefault("steps", [step("a", Observation.ok("a", URL, {"v": 1}))])
        kwargs.setdefault("rules", ruleset(HIT_RULE))
        kwargs.setdefault("correlations", ruleset(HIT_RULE).rules and __import__(
            "engine.rules", fromlist=["RuleSet"]).RuleSet())
        kwargs.setdefault("worker_options", {"heartbeat_interval": 0.01})
        return service.run_scan("scan-1", **kwargs)


class TestRun(ServiceTestCase):

    def test_returns_a_job_id(self):
        result = self.run_scan()
        self.assertTrue(result.job_id.startswith("job_"))

    def test_findings_reach_the_report(self):
        result = self.run_scan()
        self.assertEqual([group.rule_id for group in result.report.groups], ["probe.hit"])

    def test_score_is_computed(self):
        self.assertGreater(self.run_scan().score.overall, 0)

    def test_status_is_completed_without_skips(self):
        self.assertEqual(self.run_scan().status, queue.COMPLETED)

    def test_skipped_step_makes_it_partial(self):
        result = self.run_scan(steps=[step("a", Observation.skipped("a", URL, "対象外"))])
        self.assertEqual(result.status, queue.PARTIAL)
        self.assertGreater(result.report.review_count, 0)

    def test_coverage_reflects_skips(self):
        steps = [step("a", Observation.ok("a", URL, {"v": 1})),
                 step("b", Observation.skipped("b", URL, "対象外"))]
        self.assertEqual(self.run_scan(steps=steps).score.coverage, 0.5)

    def test_allowed_limits_the_steps(self):
        steps = [step("a", Observation.ok("a", URL, {"v": 1})),
                 step("b", Observation.ok("b", URL, {}))]
        result = self.run_scan(steps=steps, allowed=["a"])
        self.assertEqual(len(result.plan_result.observations), 1)

    def test_job_is_finished(self):
        self.run_scan()
        job = queue.list_jobs()[-1]
        self.assertEqual(job.status, queue.COMPLETED)

    def test_worker_log_is_attached(self):
        self.assertTrue(self.run_scan().report.log)


class TestGate(ServiceTestCase):

    def consent(self, **kwargs):
        scope = scope_module.Scope(hosts=frozenset({"example.test"}), ports=frozenset({443}))
        params = {
            "grantor": "担当者",
            "contact": "ops@example.test",
            "target": "example.test",
            "scope": scope,
            "allowed_collectors": ["a"],
        }
        params.update(kwargs)
        return consent.grant(**params)

    def verify_proof(self, host="example.test"):
        challenge = ownership.create_challenge(host, ownership.HTTP_FILE,
                                               base_url="https://example.test")
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        return challenge

    def test_missing_consent_raises(self):
        with self.assertRaises(GateError):
            self.run_scan(consent_id="nope")

    def test_consent_without_proof_raises(self):
        record = self.consent()
        with self.assertRaises(GateError):
            self.run_scan(consent_id=record.id)

    def test_consent_and_proof_allow_the_run(self):
        self.verify_proof()
        record = self.consent()
        result = self.run_scan(consent_id=record.id)
        self.assertEqual(result.status, queue.COMPLETED)

    def test_consent_restricts_the_collectors(self):
        self.verify_proof()
        record = self.consent(allowed_collectors=["a"])
        steps = [step("a", Observation.ok("a", URL, {"v": 1})),
                 step("b", Observation.ok("b", URL, {}))]
        result = self.run_scan(steps=steps, consent_id=record.id)
        self.assertEqual(len(result.plan_result.observations), 1)

class TestEnqueue(ServiceTestCase):

    def test_enqueue_returns_a_job_id(self):
        job_id = service.enqueue_scan("scan-1")
        self.assertEqual(queue.get_job(job_id).status, queue.QUEUED)


if __name__ == "__main__":
    unittest.main()