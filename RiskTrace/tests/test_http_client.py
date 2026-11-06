import unittest

from collectors.http import client
from engine.scheduler import (
    Budgets,
    BudgetExhausted,
    Cancelled,
    Scheduler,
    ScopeViolation,
)


class FakeScheduler:
    """Scheduler のうち client が使う面だけを持つ簡易版。"""

    def __init__(self, scope=None, budgets=None):
        self._inner = Scheduler(budgets or Budgets(per_host_interval=0.001), scope=scope)
        self._inner.start()

    def __getattr__(self, name):
        return getattr(self._inner, name)


def transport_of(*replies):
    remaining = list(replies)
    calls = []

    def transport(url, method, timeout):
        calls.append(url)
        status, headers, body = remaining.pop(0)
        return status, headers, body

    transport.calls = calls
    return transport


def ok(body=b"<html></html>", **headers):
    return (200, headers.items(), body)


def redirect(location):
    return (302, {"Location": location}.items(), b"")


def scheduler(**kwargs):
    return FakeScheduler(**kwargs)


class TestBasicFetch(unittest.TestCase):

    def test_returns_response(self):
        result = client.fetch("https://example.test/", scheduler(),
                              transport=transport_of(ok(**{"X-Frame-Options": "DENY"})))
        self.assertEqual(result.status, 200)
        self.assertEqual(result.first("x-frame-options"), "DENY")

    def test_consumes_one_request(self):
        sched = scheduler()
        client.fetch("https://example.test/", sched, transport=transport_of(ok()))
        self.assertEqual(sched.usage()["request"], 1)

    def test_body_is_decoded(self):
        result = client.fetch("https://example.test/", scheduler(),
                              transport=transport_of(ok(b"<p>\xe6\x97\xa5\xe6\x9c\xac</p>")))
        self.assertIn("日本", result.body)

    def test_body_is_truncated(self):
        big = b"a" * (client.MAX_BODY_BYTES + 100)
        result = client.fetch("https://example.test/", scheduler(), transport=transport_of(ok(big)))
        self.assertEqual(len(result.body), client.MAX_BODY_BYTES)

    def test_duplicate_headers_are_all_kept(self):
        reply = (200, [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")], b"")
        result = client.fetch("https://example.test/", scheduler(), transport=transport_of(reply))
        self.assertEqual(result.all("set-cookie"), ["a=1", "b=2"])


class TestRedirects(unittest.TestCase):

    def test_same_host_redirect_is_followed(self):
        transport = transport_of(redirect("/next"), ok())
        result = client.fetch("https://example.test/", scheduler(), transport=transport)
        self.assertEqual(result.url, "https://example.test/next")
        self.assertEqual(transport.calls, ["https://example.test/", "https://example.test/next"])

    def test_redirect_consumes_redirect_budget(self):
        sched = scheduler(budgets=Budgets(redirects=1, per_host_interval=0.001))
        client.fetch("https://example.test/", sched, transport=transport_of(redirect("/a"), ok()))
        self.assertEqual(sched.usage()["redirect"], 1)

    def test_redirect_budget_exhaustion_raises(self):
        sched = scheduler(budgets=Budgets(redirects=1, per_host_interval=0.001))
        with self.assertRaises(BudgetExhausted):
            client.fetch("https://example.test/", sched,
                         transport=transport_of(redirect("/a"), redirect("/b"), ok()))

    def test_hop_limit_stops_following(self):
        replies = [redirect(f"/{i}") for i in range(client.MAX_HOPS + 1)]
        result = client.fetch("https://example.test/", scheduler(),
                              transport=transport_of(*replies))
        self.assertEqual(result.status, 302)
        self.assertEqual(len(result.redirects), client.MAX_HOPS)

    def test_hop_limit_returns_the_last_response(self):
        replies = [redirect(f"/{i}") for i in range(client.MAX_HOPS + 1)]
        result = client.fetch("https://example.test/", scheduler(),
                              transport=transport_of(*replies))
        self.assertIsNotNone(result)
        self.assertEqual(result.url, f"https://example.test/{client.MAX_HOPS - 1}")
    def test_external_redirect_is_rejected(self):
        sched = scheduler(scope=lambda url: url.startswith("https://example.test"))
        with self.assertRaises(ScopeViolation):
            client.fetch("https://example.test/", sched, transport=transport_of(redirect("https://evil.test/")))

    def test_downgrade_is_recorded(self):
        sched = scheduler(scope=lambda url: True)
        result = client.fetch("https://example.test/", sched,
                              transport=transport_of(redirect("http://example.test/"), ok()))
        self.assertTrue(result.downgraded)

    def test_upgrade_is_not_a_downgrade(self):
        sched = scheduler(scope=lambda url: True)
        result = client.fetch("http://example.test/", sched,
                              transport=transport_of(redirect("https://example.test/"), ok()))
        self.assertFalse(result.downgraded)

    def test_redirect_without_location_stops(self):
        transport = transport_of((302, {"X": "y"}.items(), b""))
        result = client.fetch("https://example.test/", scheduler(), transport=transport)
        self.assertEqual(result.status, 302)
        self.assertEqual(len(transport.calls), 1)


class TestScopeAndControl(unittest.TestCase):

    def test_out_of_scope_start_is_rejected(self):
        sched = scheduler(scope=lambda url: False)
        with self.assertRaises(ScopeViolation):
            client.fetch("https://example.test/", sched, transport=transport_of(ok()))

    def test_cancellation_is_checked(self):
        sched = scheduler()
        sched.cancel("停止")
        with self.assertRaises(Cancelled):
            client.fetch("https://example.test/", sched, transport=transport_of(ok()))

    def test_request_budget_is_enforced(self):
        sched = scheduler(budgets=Budgets(requests=1, per_host_interval=0.001))
        client.fetch("https://example.test/", sched, transport=transport_of(ok()))
        with self.assertRaises(BudgetExhausted):
            client.fetch("https://example.test/", sched, transport=transport_of(ok()))


class TestRetry(unittest.TestCase):

    def test_retry_happens_once_on_transport_error(self):
        import requests
        attempts = []

        def transport(url, method, timeout):
            attempts.append(url)
            if len(attempts) == 1:
                raise requests.ConnectionError("boom")
            return 200, {"X": "y"}.items(), b""

        sched = scheduler()
        result = client.fetch("https://example.test/", sched, transport=transport)
        self.assertEqual(result.status, 200)
        self.assertEqual(sched.usage()["retry"], 1)

    def test_retry_exhaustion_raises_fetch_error(self):
        import requests

        def transport(url, method, timeout):
            raise requests.ConnectionError("boom")

        with self.assertRaises(client.FetchError):
            client.fetch("https://example.test/", scheduler(), transport=transport)

    def test_no_retry_without_budget(self):
        import requests
        sched = scheduler(budgets=Budgets(retries=1, per_host_interval=0.001))
        sched.reserve("retry")

        def transport(url, method, timeout):
            raise requests.ConnectionError("boom")

        with self.assertRaises(client.FetchError):
            client.fetch("https://example.test/", sched, transport=transport)


if __name__ == "__main__":
    unittest.main()