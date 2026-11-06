import threading
import unittest

from engine.scheduler import (
    BudgetExhausted,
    Budgets,
    Cancelled,
    REDIRECT,
    REQUEST,
    RETRY,
    Scheduler,
    ScopeViolation,
    TimeBudgetExhausted,
)


class FakeClock:
    """sleep で進む時計。レート制限を実時間なしで検証する。"""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def make(budgets=None, scope=None, clock=None):
    clock = clock or FakeClock()
    scheduler = Scheduler(budgets or Budgets(), scope=scope, clock=clock, sleeper=clock.sleep)
    scheduler.start()
    return scheduler, clock


class TestBudgets(unittest.TestCase):

    def test_reserve_decrements_request_budget(self):
        scheduler, _ = make(Budgets(requests=3))
        scheduler.reserve()
        scheduler.reserve()
        self.assertEqual(scheduler.remaining(REQUEST), 1)
        self.assertEqual(scheduler.usage()[REQUEST], 2)

    def test_try_reserve_returns_false_when_exhausted(self):
        scheduler, _ = make(Budgets(requests=1))
        self.assertTrue(scheduler.try_reserve())
        self.assertFalse(scheduler.try_reserve())
        self.assertTrue(scheduler.budget_exhausted)

    def test_reserve_raises_when_exhausted(self):
        scheduler, _ = make(Budgets(requests=1))
        scheduler.reserve()
        with self.assertRaises(BudgetExhausted):
            scheduler.reserve()

    def test_exhaustion_does_not_raise_by_itself(self):
        scheduler, _ = make(Budgets(requests=1))
        scheduler.try_reserve()
        self.assertFalse(scheduler.try_reserve())
        self.assertEqual(scheduler.remaining(REQUEST), 0)

    def test_budgets_are_independent(self):
        scheduler, _ = make(Budgets(requests=5, redirects=1, retries=1))
        scheduler.reserve(REDIRECT)
        self.assertFalse(scheduler.try_reserve(REDIRECT))
        self.assertEqual(scheduler.remaining(REQUEST), 5)
        self.assertTrue(scheduler.try_reserve(RETRY))

    def test_retry_consumes_its_own_budget(self):
        scheduler, _ = make(Budgets(requests=5, retries=1))
        scheduler.reserve(RETRY)
        self.assertEqual(scheduler.usage()[RETRY], 1)
        self.assertEqual(scheduler.usage()[REQUEST], 0)

    def test_unknown_kind_is_rejected(self):
        scheduler, _ = make()
        with self.assertRaises(ValueError):
            scheduler.try_reserve("dns")

    def test_amount_below_one_is_rejected(self):
        scheduler, _ = make()
        with self.assertRaises(ValueError):
            scheduler.try_reserve(REQUEST, 0)


class TestTimeBudget(unittest.TestCase):

    def test_time_budget_expires(self):
        scheduler, clock = make(Budgets(seconds=10))
        clock.now += 10
        with self.assertRaises(TimeBudgetExhausted):
            scheduler.check_time()

    def test_remaining_seconds_counts_down(self):
        scheduler, clock = make(Budgets(seconds=10))
        clock.now += 4
        self.assertAlmostEqual(scheduler.remaining_seconds(), 6)

    def test_remaining_seconds_never_negative(self):
        scheduler, clock = make(Budgets(seconds=5))
        clock.now += 99
        self.assertEqual(scheduler.remaining_seconds(), 0.0)

    def test_http_timeout_is_clamped_by_remaining_time(self):
        scheduler, clock = make(Budgets(seconds=100, http_timeout=(5.0, 30.0)))
        clock.now += 98
        self.assertEqual(scheduler.http_timeout(), (2.0, 2.0))

    def test_http_timeout_without_pressure_uses_config(self):
        scheduler, _ = make(Budgets(seconds=100, http_timeout=(5.0, 30.0)))
        self.assertEqual(scheduler.http_timeout(), (5.0, 30.0))

    def test_http_timeout_raises_when_out_of_time(self):
        scheduler, clock = make(Budgets(seconds=5))
        clock.now += 10
        with self.assertRaises(TimeBudgetExhausted):
            scheduler.http_timeout()


class TestCancellation(unittest.TestCase):

    def test_cancel_sets_flag_and_reason(self):
        scheduler, _ = make()
        scheduler.cancel("予算都合")
        self.assertTrue(scheduler.cancelled)
        self.assertEqual(scheduler.cancel_reason, "予算都合")

    def test_check_cancel_raises(self):
        scheduler, _ = make()
        scheduler.cancel()
        with self.assertRaises(Cancelled):
            scheduler.check_cancel()

    def test_first_reason_wins(self):
        scheduler, _ = make()
        scheduler.cancel("最初")
        scheduler.cancel("あとから")
        self.assertEqual(scheduler.cancel_reason, "最初")

    def test_external_event_can_cancel(self):
        event = threading.Event()
        scheduler = Scheduler(Budgets(), cancel_event=event)
        event.set()
        self.assertTrue(scheduler.cancelled)

    def test_slot_rejects_cancelled_job(self):
        scheduler, _ = make()
        scheduler.cancel()
        with self.assertRaises(Cancelled):
            with scheduler.slot("example.test"):
                pass


class TestScope(unittest.TestCase):

    def test_scope_is_not_enforced_by_default(self):
        scheduler, _ = make()
        self.assertFalse(scheduler.scope_enforced)
        scheduler.check_scope("https://anything.test/")

    def test_allowed_target_passes(self):
        scheduler, _ = make(scope=lambda target: target.startswith("https://ok.test"))
        scheduler.check_scope("https://ok.test/a")

    def test_disallowed_target_raises_and_is_logged(self):
        scheduler, _ = make(scope=lambda target: False)
        with self.assertRaises(ScopeViolation):
            scheduler.check_scope("https://bad.test/")
        events = [entry["event"] for entry in scheduler.log()]
        self.assertIn("scope_violation", events)


class TestRateAndConcurrency(unittest.TestCase):

    def test_first_request_to_a_host_does_not_wait(self):
        scheduler, clock = make(Budgets(per_host_interval=5.0))
        with scheduler.slot("a.test"):
            pass
        self.assertEqual(clock.slept, [])

    def test_second_request_to_the_same_host_waits(self):
        scheduler, clock = make(Budgets(per_host_interval=1.0))
        with scheduler.slot("a.test"):
            pass
        with scheduler.slot("a.test"):
            pass
        self.assertGreaterEqual(sum(clock.slept), 1.0)

    def test_different_hosts_do_not_wait_for_each_other(self):
        scheduler, clock = make(Budgets(per_host_interval=1.0))
        with scheduler.slot("a.test"):
            pass
        with scheduler.slot("b.test"):
            pass
        self.assertEqual(clock.slept, [])

    def test_inflight_is_released_after_the_block(self):
        scheduler, _ = make()
        self.assertEqual(scheduler.inflight, 0)
        with scheduler.slot("a.test"):
            self.assertEqual(scheduler.inflight, 1)
        self.assertEqual(scheduler.inflight, 0)

    def test_inflight_is_released_on_exception(self):
        scheduler, _ = make()
        with self.assertRaises(RuntimeError):
            with scheduler.slot("a.test"):
                raise RuntimeError("boom")
        self.assertEqual(scheduler.inflight, 0)

    def test_concurrency_is_capped(self):
        scheduler, _ = make(Budgets(max_inflight=1, per_host_interval=0.01))
        peak = []
        order = []

        def worker(name):
            with scheduler.slot(f"{name}.test"):
                peak.append(scheduler.inflight)
                order.append(name)

        threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(order), 3)
        self.assertEqual(max(peak), 1)


class TestBudgetsValidation(unittest.TestCase):

    def test_zero_requests_is_rejected(self):
        with self.assertRaises(ValueError):
            Budgets(requests=0)

    def test_zero_seconds_is_rejected(self):
        with self.assertRaises(ValueError):
            Budgets(seconds=0)

    def test_bad_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            Budgets(http_timeout=(0.0, 5.0))

    def test_defaults_are_usable(self):
        budgets = Budgets()
        self.assertGreater(budgets.requests, 0)
        self.assertGreater(budgets.max_inflight, 0)


class TestLogAndSnapshot(unittest.TestCase):

    def test_record_returns_the_entry(self):
        scheduler, _ = make()
        entry = scheduler.record("collector_start", collector="http_headers")
        self.assertEqual(entry["event"], "collector_start")
        self.assertEqual(scheduler.log()[0]["collector"], "http_headers")

    def test_snapshot_contains_control_state(self):
        scheduler, _ = make(Budgets(requests=2))
        scheduler.reserve()
        snap = scheduler.snapshot()
        self.assertEqual(snap["usage"][REQUEST], 1)
        self.assertEqual(snap["remaining"][REQUEST], 1)
        self.assertFalse(snap["cancelled"])

    def test_snapshot_is_a_copy(self):
        scheduler, _ = make()
        scheduler.log().append({"event": "x"})
        self.assertEqual(len(scheduler.log()), 0)


if __name__ == "__main__":
    unittest.main()