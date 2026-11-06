import unittest

from collectors.http import cors
from engine.scheduler import Budgets, Cancelled, Scheduler

URL = "https://example.test/api"


def scheduler(scope=None, budgets=None):
    instance = Scheduler(
        budgets or Budgets(per_host_interval=0.001),
        scope=scope or (lambda url: True),
    )
    instance.start()
    return instance


def send_with(headers_=None, status=200):
    """固定の応答ヘッダーを返す send。送った内容を記録する。"""
    calls = []

    def send(url, method, timeout, headers):
        calls.append({"url": url, "method": method, "headers": dict(headers)})
        return status, list((headers_ or {}).items()), b""

    send.calls = calls
    return send


def collect(**kwargs):
    send = kwargs.pop("send", None) or send_with()
    return cors.collect(
        URL,
        kwargs.pop("sched", None) or scheduler(),
        send=send,
        **kwargs,
    )


class TestRequest(unittest.TestCase):

    def test_origin_header_is_sent(self):
        send = send_with()
        collect(send=send)
        self.assertEqual(send.calls[0]["headers"]["Origin"], cors.PROBE_ORIGIN)

    def test_get_is_sent_first(self):
        send = send_with()
        collect(send=send)
        self.assertEqual(send.calls[0]["method"], "GET")

    def test_preflight_sends_request_method(self):
        send = send_with()
        collect(send=send)
        self.assertEqual(send.calls[1]["method"], "OPTIONS")
        self.assertEqual(send.calls[1]["headers"]["Access-Control-Request-Method"], "GET")

    def test_preflight_can_be_disabled(self):
        send = send_with()
        collect(send=send, preflight=False)
        self.assertEqual([call["method"] for call in send.calls], ["GET"])


class TestHeaders(unittest.TestCase):

    def test_reflected_origin_is_flagged(self):
        observation = collect(send=send_with({"Access-Control-Allow-Origin": cors.PROBE_ORIGIN}))
        self.assertTrue(observation.data["reflected"])
        self.assertFalse(observation.data["wildcard"])

    def test_wildcard_is_flagged(self):
        observation = collect(send=send_with({"Access-Control-Allow-Origin": "*"}))
        self.assertTrue(observation.data["wildcard"])
        self.assertFalse(observation.data["reflected"])

    def test_null_origin_is_flagged(self):
        observation = collect(send=send_with({"Access-Control-Allow-Origin": "null"}))
        self.assertTrue(observation.data["null"])

    def test_missing_header_is_recorded_as_none(self):
        observation = collect(send=send_with())
        self.assertIsNone(observation.data["allow_origin"])
        self.assertFalse(observation.data["reflected"])

    def test_credentials_is_flagged(self):
        observation = collect(
            send=send_with({"Access-Control-Allow-Credentials": "true"})
        )
        self.assertTrue(observation.data["credentials"])

    def test_vary_origin_is_flagged(self):
        observation = collect(send=send_with({"Vary": "Origin"}))
        self.assertTrue(observation.data["vary_has_origin"])

    def test_multiple_origins_are_split(self):
        observation = collect(
            send=send_with({"Access-Control-Allow-Origin": "https://a.test, https://b.test"})
        )
        self.assertEqual(
            observation.data["probes"][0]["allow_origin_list"],
            ["https://a.test", "https://b.test"],
        )

    def test_preflight_405_is_not_supported(self):
        send = send_with()
        observation = cors.collect(URL, scheduler(), send=lambda *a: (405, [], b""))
        self.assertFalse(observation.data["preflight_supported"])

    def test_location_is_recorded_without_following(self):
        observation = collect(send=send_with({"Location": "/elsewhere"}))
        self.assertEqual(observation.data["probes"][0]["location"], "/elsewhere")


class TestControl(unittest.TestCase):

    def test_two_requests_are_consumed(self):
        sched = scheduler()
        cors.collect(URL, sched, send=send_with())
        self.assertEqual(sched.usage()["request"], 2)

    def test_budget_exhaustion_truncates_without_raising(self):
        observation = collect(
            sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        sched = scheduler()
        sched.cancel("test")
        with self.assertRaises(Cancelled):
            cors.collect(URL, sched, send=send_with())

    def test_transport_error_is_an_error_observation(self):
        def boom(url, method, timeout, headers):
            raise OSError("no route")

        observation = cors.collect(URL, scheduler(), send=boom)
        self.assertTrue(observation.is_error)

    def test_no_verdict_is_recorded(self):
        observation = collect()
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)


if __name__ == "__main__":
    unittest.main()