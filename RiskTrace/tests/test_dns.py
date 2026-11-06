import json
import unittest

from collectors.dns import records
from engine.scheduler import Budgets, Scheduler


def scheduler():
    instance = Scheduler(Budgets(requests=200, per_host_interval=0.001))
    instance.start()
    return instance


def answer(*values):
    return json.dumps({
        "Status": 0,
        "Answer": [{"type": 16, "data": f'"{v}"'} for v in values],
    })


def fake_fetch(table):
    calls = []

    def fetch(url):
        calls.append(url)
        for key, values in table.items():
            if f"name={key}&" in url:
                return 200, answer(*values)
        return 200, answer()

    fetch.calls = calls
    return fetch


def collect(table=None, **kwargs):
    return records.collect("example.test", scheduler(), fetch=fake_fetch(table or {}), **kwargs)


class TestSpf(unittest.TestCase):

    def test_missing_spf_is_recorded_as_absent(self):
        data = collect().data
        self.assertFalse(data["spf"]["present"])
        self.assertEqual(data["spf"]["count"], 0)

    def test_present_spf_is_recorded(self):
        data = collect({"example.test": ["v=spf1 include:_spf.example.test -all"]}).data
        self.assertTrue(data["spf"]["present"])
        self.assertEqual(data["spf"]["policy"], "-all")

    def test_softfail_policy_is_recorded(self):
        data = collect({"example.test": ["v=spf1 ~all"]}).data
        self.assertEqual(data["spf"]["policy"], "~all")

    def test_neutral_policy_is_recorded(self):
        data = collect({"example.test": ["v=spf1 ?all"]}).data
        self.assertEqual(data["spf"]["policy"], "?all")

    def test_missing_qualifier_is_none(self):
        data = collect({"example.test": ["v=spf1 include:_spf.example.test"]}).data
        self.assertIsNone(data["spf"]["policy"])

    def test_multiple_spf_records_are_counted(self):
        data = collect({"example.test": ["v=spf1 -all", "v=spf1 ~all"]}).data
        self.assertTrue(data["spf"]["multiple"])
        self.assertEqual(data["spf"]["count"], 2)

    def test_non_spf_txt_is_ignored(self):
        data = collect({"example.test": ["google-site-verification=abc"]}).data
        self.assertFalse(data["spf"]["present"])


class TestDmarc(unittest.TestCase):

    def test_missing_dmarc_is_recorded(self):
        self.assertFalse(collect().data["dmarc"]["present"])

    def test_dmarc_policy_is_recorded(self):
        data = collect({"_dmarc.example.test": ["v=DMARC1; p=reject; rua=mailto:a@example.test"]}).data
        self.assertTrue(data["dmarc"]["present"])
        self.assertEqual(data["dmarc"]["policy"], "reject")

    def test_none_policy_is_recorded(self):
        data = collect({"_dmarc.example.test": ["v=DMARC1; p=none"]}).data
        self.assertEqual(data["dmarc"]["policy"], "none")

    def test_dmarc_without_p_is_none(self):
        data = collect({"_dmarc.example.test": ["v=DMARC1; rua=mailto:a@example.test"]}).data
        self.assertIsNone(data["dmarc"]["policy"])


class TestDkim(unittest.TestCase):

    def test_no_selector_found_is_not_a_claim_of_absence(self):
        data = collect().data
        self.assertFalse(data["dkim"]["resolved"])
        self.assertEqual(data["dkim"]["selectors_found"], [])

    def test_found_selector_is_recorded(self):
        table = {"google._domainkey.example.test": ["v=DKIM1; p=MIIBIjANBg"]}
        data = collect(table).data
        self.assertEqual(data["dkim"]["selectors_found"], ["google"])
        self.assertTrue(data["dkim"]["resolved"])

    def test_tried_selectors_are_reported(self):
        data = collect(selectors=("default", "s1")).data
        self.assertEqual(data["dkim"]["selectors_tried"], ["default", "s1"])

    def test_one_query_per_selector(self):
        fetch = fake_fetch({})
        records.collect("example.test", scheduler(), selectors=("a", "b"), fetch=fetch)
        dkim_calls = [call for call in fetch.calls if "_domainkey" in call]
        self.assertEqual(len(dkim_calls), 2)


class TestErrors(unittest.TestCase):

    def test_http_error_becomes_error_observation(self):
        observation = records.collect("example.test", scheduler(), fetch=lambda url: (503, ""))
        self.assertTrue(observation.is_error)

    def test_broken_json_becomes_error_observation(self):
        observation = records.collect("example.test", scheduler(), fetch=lambda url: (200, "nope"))
        self.assertTrue(observation.is_error)

    def test_dkim_query_failure_does_not_fail_the_whole_observation(self):
        def fetch(url):
            if "_domainkey" in url:
                return 500, ""
            return 200, answer()

        observation = records.collect("example.test", scheduler(), fetch=fetch)
        self.assertTrue(observation.is_ok)
        self.assertFalse(observation.data["dkim"]["resolved"])


class TestControl(unittest.TestCase):

    def test_each_query_consumes_a_request(self):
        instance = scheduler()
        records.collect("example.test", instance, selectors=("a",), fetch=fake_fetch({}))
        self.assertEqual(instance.usage()["request"], 3)

    def test_collector_does_not_decide_severity(self):
        self.assertNotIn("severity", collect().data)

    def test_domain_is_the_subject(self):
        self.assertEqual(collect().subject, "example.test")


if __name__ == "__main__":
    unittest.main()