import json
import unittest

from collectors.explore import subdomains
from engine.scheduler import Budgets, Cancelled, Scheduler


def scheduler(budgets=None):
    instance = Scheduler(budgets or Budgets(per_host_interval=0.001))
    instance.start()
    return instance


def answer(*addresses, status=0):
    return json.dumps({
        "Status": status,
        "Answer": [{"name": "x.example.test", "type": 1, "data": ip} for ip in addresses],
    })


def fetch_from(table):
    calls = []

    def fetch(url):
        calls.append(url)
        for name, reply in table.items():
            if f"name={name}&" in url:
                return reply
        return 200, answer(status=3)

    fetch.calls = calls
    return fetch


def collect(table=None, names=("www",), **kwargs):
    return subdomains.collect(
        "example.test",
        kwargs.pop("sched", None) or scheduler(),
        names=names,
        fetch=fetch_from(table or {}),
        **kwargs,
    )


class TestLookup(unittest.TestCase):

    def test_resolved_name_keeps_addresses(self):
        observation = collect({"www.example.test": (200, answer("192.0.2.10"))})
        entry = observation.data["names"][0]
        self.assertEqual(entry["state"], "resolved")
        self.assertEqual(entry["addresses"], ["192.0.2.10"])
        self.assertEqual(observation.data["resolved"], ["www.example.test"])

    def test_nxdomain_is_distinguished(self):
        observation = collect({"www.example.test": (200, answer(status=3))})
        self.assertEqual(observation.data["names"][0]["state"], "nxdomain")

    def test_empty_answer_is_not_nxdomain(self):
        observation = collect({"www.example.test": (200, answer())})
        self.assertEqual(observation.data["names"][0]["state"], "no_answer")

    def test_other_dns_status_is_error(self):
        observation = collect({"www.example.test": (200, json.dumps({"Status": 2}))})
        self.assertEqual(observation.data["names"][0]["state"], "error")

    def test_http_error_is_error(self):
        observation = collect({"www.example.test": (503, "")})
        self.assertEqual(observation.data["names"][0]["state"], "error")

    def test_broken_json_is_error(self):
        observation = collect({"www.example.test": (200, "not json")})
        self.assertEqual(observation.data["names"][0]["state"], "error")

    def test_cname_answers_are_ignored(self):
        body = json.dumps({
            "Status": 0,
            "Answer": [{"name": "www.example.test", "type": 5, "data": "cdn.test"}],
        })
        observation = collect({"www.example.test": (200, body)})
        self.assertEqual(observation.data["names"][0]["state"], "no_answer")


class TestScope(unittest.TestCase):

    def test_apex_is_the_last_two_labels(self):
        observation = subdomains.collect(
            "https://deep.www.example.test/", scheduler(), names=("www",),
            fetch=fetch_from({}),
        )
        self.assertEqual(observation.data["apex"], "example.test")
        self.assertEqual(observation.subject, "deep.www.example.test")

    def test_host_can_come_from_a_url(self):
        observation = subdomains.collect(
            "https://example.test/x", scheduler(), names=("www",), fetch=fetch_from({}),
        )
        self.assertEqual(observation.subject, "example.test")

    def test_resolved_names_are_marked_out_of_scope(self):
        observation = collect({"www.example.test": (200, answer("192.0.2.10"))})
        self.assertFalse(observation.data["in_scope"])

    def test_missing_host_is_an_error(self):
        observation = subdomains.collect("", scheduler(), fetch=fetch_from({}))
        self.assertTrue(observation.is_error)


class TestControl(unittest.TestCase):

    def test_one_query_per_name(self):
        instance = scheduler()
        subdomains.collect("example.test", instance, names=("www", "api"),
                           fetch=fetch_from({}))
        self.assertEqual(instance.usage()["request"], 2)

    def test_names_are_capped(self):
        observation = collect(names=tuple(f"n{i}" for i in range(50)))
        self.assertEqual(len(observation.data["names"]), subdomains.MAX_NAMES)

    def test_budget_exhaustion_truncates_without_raising(self):
        observation = collect(
            {}, names=("www", "api"),
            sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        instance = scheduler()
        instance.cancel("test")
        with self.assertRaises(Cancelled):
            subdomains.collect("example.test", instance, names=("www",), fetch=fetch_from({}))

    def test_no_verdict_is_recorded(self):
        observation = collect({})
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)

    def test_counts_are_summarised(self):
        observation = collect(
            {"www.example.test": (200, answer("192.0.2.10")),
             "api.example.test": (200, answer(status=3))},
            names=("www", "api"),
        )
        self.assertEqual(observation.data["counts"]["resolved"], 1)
        self.assertEqual(observation.data["counts"]["nxdomain"], 1)


if __name__ == "__main__":
    unittest.main()