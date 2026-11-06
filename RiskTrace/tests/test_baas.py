import json
import unittest

from collectors.baas import endpoints
from engine.scheduler import Budgets, Cancelled, Scheduler

URL = "https://example.test/"

SUPA = "https://abcdefghij1234567890.supabase.co"
FIRE = "https://demo-project.firebaseio.com"


def scheduler(budgets=None):
    instance = Scheduler(budgets or Budgets(per_host_interval=0.001))
    instance.start()
    return instance


def fetch_from(table):
    calls = []

    def fetch(url):
        calls.append(url)
        return table.get(url, (404, "{}"))

    fetch.calls = calls
    return fetch


def collect(text="", table=None, **kwargs):
    return endpoints.collect(
        [(URL, text)],
        kwargs.pop("sched", None) or scheduler(),
        fetch=fetch_from(table or {}),
        **kwargs,
    )


class TestExtract(unittest.TestCase):

    def test_supabase_ref_is_found(self):
        self.assertEqual(endpoints.extract_refs(f'<script src="{SUPA}/x.js">'),
                         [(endpoints.SUPABASE, "abcdefghij1234567890")])

    def test_firebase_ref_is_found(self):
        self.assertEqual(endpoints.extract_refs(f'"{FIRE}/x.json"'),
                         [(endpoints.FIREBASE, "demo-project")])

    def test_web_app_domain_is_found(self):
        self.assertEqual(endpoints.extract_refs("https://demo-project.web.app/"),
                         [(endpoints.FIREBASE, "demo-project")])

    def test_duplicates_are_removed(self):
        self.assertEqual(len(endpoints.extract_refs(f"{SUPA} {SUPA}")), 1)

    def test_short_ref_is_ignored(self):
        self.assertEqual(endpoints.extract_refs("https://abc.supabase.co"), [])

    def test_asset_urls_are_scanned(self):
        observation = endpoints.collect(
            [], scheduler(), asset_urls=[f"{SUPA}/storage/v1/object/x.png"],
            fetch=fetch_from({}),
        )
        self.assertEqual(observation.data["refs"][0]["ref"], "abcdefghij1234567890")


class TestProbe(unittest.TestCase):

    def test_supabase_rest_is_called(self):
        fetch = fetch_from({})
        endpoints.collect([(URL, SUPA)], scheduler(), fetch=fetch)
        self.assertEqual(fetch.calls, [SUPA + "/rest/v1/"])

    def test_firebase_calls_both_endpoints(self):
        fetch = fetch_from({})
        endpoints.collect([(URL, FIRE)], scheduler(), fetch=fetch)
        self.assertEqual(len(fetch.calls), 2)

    def test_reachable_status_is_recorded(self):
        observation = collect(SUPA, {SUPA + "/rest/v1/": (401, "{}")})
        self.assertTrue(observation.data["probes"][0]["reachable"])
        self.assertEqual(observation.data["probes"][0]["status"], 401)

    def test_openapi_flag(self):
        body = json.dumps({"openapi": "3.0.0", "paths": {}})
        observation = collect(SUPA, {SUPA + "/rest/v1/": (200, body)})
        self.assertTrue(observation.data["probes"][0]["openapi"])

    def test_api_key_flag(self):
        body = json.dumps({"apiKey": "AIza-x", "authDomain": "demo.firebaseapp.com"})
        observation = collect(FIRE, {FIRE + "/.json?shallow=true": (200, body)})
        self.assertTrue(observation.data["probes"][0]["has_api_key"])
        self.assertEqual(observation.data["probes"][0]["auth_domain"], "demo.firebaseapp.com")

    def test_server_error_is_not_reachable(self):
        observation = collect(SUPA, {SUPA + "/rest/v1/": (503, "")})
        self.assertFalse(observation.data["probes"][0]["reachable"])

    def test_fetch_error_is_recorded(self):
        def boom(url):
            raise OSError("no route")

        observation = endpoints.collect([(URL, SUPA)], scheduler(), fetch=boom)
        self.assertTrue(observation.is_ok)
        self.assertIn("no route", observation.data["probes"][0]["error"])


class TestControl(unittest.TestCase):

    def test_no_refs_returns_empty_observation(self):
        observation = collect("nothing here")
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["refs"], [])
        self.assertIn("見つかりません", observation.note)

    def test_refs_are_capped(self):
        text = " ".join(f"https://ref{i:015d}.supabase.co" for i in range(10))
        observation = collect(text)
        self.assertEqual(len(observation.data["refs"]), endpoints.MAX_REFS)

    def test_one_request_per_endpoint(self):
        instance = scheduler()
        endpoints.collect([(URL, SUPA)], instance, fetch=fetch_from({}))
        self.assertEqual(instance.usage()["request"], 1)

    def test_budget_exhaustion_truncates_without_raising(self):
        observation = collect(
            FIRE, sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        instance = scheduler()
        instance.cancel("test")
        with self.assertRaises(Cancelled):
            endpoints.collect([(URL, SUPA)], instance, fetch=fetch_from({}))

    def test_subject_is_the_first_document(self):
        observation = collect(SUPA)
        self.assertEqual(observation.subject, URL)

    def test_no_verdict_is_recorded(self):
        observation = collect(SUPA)
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)


if __name__ == "__main__":
    unittest.main()