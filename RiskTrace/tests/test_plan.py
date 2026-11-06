import tempfile
import unittest
from pathlib import Path

from database import db as db_module
from engine import plan
from engine.observations import Observation
from engine.scheduler import Budgets, Cancelled, Scheduler
from evidence import store
from evidence.store import EvidenceError

URL = "https://example.test/"


def scheduler():
    instance = Scheduler(Budgets(per_host_interval=0.001))
    instance.start()
    return instance


def step(name, result=None, needs=(), error=None):
    calls = []

    def collect(target, sched, context):
        calls.append(target)
        if error is not None:
            raise error
        return result

    collect.calls = calls
    return plan.Step(name, collect, needs=needs), calls


class PlanTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False
        store.init_evidence()

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def run_plan(self, steps, **kwargs):
        kwargs.setdefault("rules", plan.RuleSet())
        kwargs.setdefault("correlations", plan.RuleSet())
        return plan.run_plan(URL, scheduler(), steps=steps, **kwargs)


class TestExecution(PlanTestCase):

    def test_steps_run_in_order(self):
        first, first_calls = step("a", Observation.ok("a", URL, {"v": 1}))
        second, second_calls = step("b", Observation.ok("b", URL, {"v": 2}))
        result = self.run_plan([first, second])
        self.assertEqual(len(result.observations), 2)
        self.assertEqual(first_calls, [URL])
        self.assertEqual(second_calls, [URL])

    def test_missing_need_skips_the_step(self):
        dependent, calls = step("b", Observation.ok("b", URL, {}), needs=("a",))
        result = self.run_plan([dependent])
        self.assertEqual(result.observations, ())
        self.assertEqual(dict(result.skipped)["b"], "needs:a")
        self.assertEqual(calls, [])

    def test_failed_need_skips_the_step(self):
        broken, _calls = step("a", error=RuntimeError("boom"))
        dependent, calls = step("b", Observation.ok("b", URL, {}), needs=("a",))
        result = self.run_plan([broken, dependent])
        self.assertEqual(dict(result.skipped)["b"], "needs:a")
        self.assertEqual(calls, [])

    def test_not_consented_step_is_skipped(self):
        _first, calls = step("a", Observation.ok("a", URL, {}))
        result = self.run_plan([_first], allowed=["other"])
        self.assertEqual(result.observations, ())
        self.assertEqual(dict(result.skipped)["a"], "not_consented")
        self.assertEqual(calls, [])

    def test_allowed_step_runs(self):
        first, _calls = step("a", Observation.ok("a", URL, {}))
        result = self.run_plan([first], allowed=["a"])
        self.assertEqual(len(result.observations), 1)

    def test_collector_error_is_recorded_and_plan_continues(self):
        broken, _calls = step("a", error=RuntimeError("boom"))
        ok, _ok_calls = step("b", Observation.ok("b", URL, {}))
        result = self.run_plan([broken, ok])
        self.assertEqual(dict(result.skipped)["a"], "error:RuntimeError")
        self.assertEqual(len(result.observations), 1)

    def test_empty_result_is_recorded(self):
        empty, _calls = step("a", None)
        result = self.run_plan([empty])
        self.assertEqual(dict(result.skipped)["a"], "empty")

    def test_cancellation_propagates(self):
        sched = scheduler()
        sched.cancel("test")
        with self.assertRaises(Cancelled):
            plan.run_plan(URL, sched, steps=[step("a", Observation.ok("a", URL, {}))[0]])

    def test_empty_target_raises(self):
        with self.assertRaises(ValueError):
            plan.run_plan(" ", scheduler(), steps=[])


class TestEvidence(PlanTestCase):

    def test_usable_observation_is_saved(self):
        first, _calls = step("a", Observation.ok("a", URL, {"v": 1}))
        result = self.run_plan([first], job_id="job_1")
        self.assertTrue(result.observations[0].has_evidence)
        self.assertEqual(store.get(result.observations[0].evidence_id).job_id, "job_1")

    def test_skipped_observation_is_not_saved(self):
        skipped, _calls = step("a", Observation.skipped("a", URL, "対象外"))
        result = self.run_plan([skipped])
        self.assertFalse(result.observations[0].has_evidence)

    def test_saving_can_be_disabled(self):
        first, _calls = step("a", Observation.ok("a", URL, {"v": 1}))
        result = self.run_plan([first], save_evidence=False)
        self.assertFalse(result.observations[0].has_evidence)

    def test_urls_are_collected_for_later_steps(self):
        produced = Observation.ok("a", URL, {"urls": [URL + "x"]})
        first, _calls = step("a", produced)
        seen = {}

        def collect(target, sched, context):
            seen.update(context)
            return Observation.ok("b", URL, {})

        result = self.run_plan([first, plan.Step("b", collect)])
        self.assertEqual(seen["urls"], [URL + "x"])
        self.assertEqual(len(result.observations), 2)


class TestRules(PlanTestCase):

    def test_findings_are_produced(self):
        from engine.rules import load_rules_from_text

        text = """
- id: probe.hit
  title: t
  severity: LOW
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
        ruleset = load_rules_from_text(text, "probe.yaml")
        first, _calls = step("a", Observation.ok("a", URL, {"v": 1}))
        result = self.run_plan([first], rules=ruleset)
        self.assertEqual(len(result.findings), 1)

    def test_no_findings_without_requirements(self):
        from engine.rules import load_rules_from_text

        text = """
- id: probe.hit
  title: t
  severity: LOW
  confidence: high
  requires:
    - consent
  collectors:
    - a
  when:
    obs:
      collector: a
      key: v
      op: present
  message: m
  why: w
  fix: f
  verify: v
"""
        ruleset = load_rules_from_text(text, "probe.yaml")
        first, _calls = step("a", Observation.ok("a", URL, {"v": 1}))
        result = self.run_plan([first], rules=ruleset)
        self.assertEqual(result.findings, ())


class TestRunner(PlanTestCase):

    def setUp(self):
        super().setUp()
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

    def job(self, scan_id="scan-1"):
        return type("Job", (), {"id": "job-1", "scan_id": scan_id})()

    def test_target_is_read_from_the_scan(self):
        self.assertEqual(plan.target_of(self.job()), URL)

    def test_missing_scan_raises(self):
        with self.assertRaises(ValueError):
            plan.target_of(self.job("nope"))

    def test_missing_scan_id_raises(self):
        with self.assertRaises(ValueError):
            plan.target_of(type("Job", (), {"id": "job-1"})())

    def test_runner_reports_partial_when_a_step_is_skipped(self):
        from database import queue as queue_module

        skipped, _calls = step("a", Observation.skipped("a", URL, "対象外"))
        runner = plan.make_runner(steps=[skipped])
        result = runner(self.job(), scheduler())
        self.assertEqual(result.status, queue_module.PARTIAL)
        self.assertIn("飛ばした", result.note)

    def test_runner_reports_completed_without_skips(self):
        from database import queue as queue_module

        ok, _calls = step("a", Observation.ok("a", URL, {"v": 1}))
        runner = plan.make_runner(steps=[ok])
        result = runner(self.job(), scheduler())
        self.assertEqual(result.status, queue_module.COMPLETED)
        self.assertIsNone(result.note)

class TestDefaultRules(unittest.TestCase):

    def test_all_rules_are_loaded(self):
        from engine import plan

        ruleset = plan.load_all_rules()
        self.assertGreater(len(ruleset), 0)

    def test_correlation_rules_are_excluded(self):
        from engine import plan

        ids = plan.load_all_rules().ids
        self.assertFalse(any(rule_id.startswith("correlation.") for rule_id in ids))

    def test_header_rules_are_present(self):
        from engine import plan

        self.assertIn("headers.csp-missing", plan.load_all_rules().ids)

if __name__ == "__main__":
    unittest.main()