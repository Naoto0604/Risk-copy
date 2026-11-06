import unittest

from collectors.http import redirects
from engine.observations import Observation
from engine.rule_runner import ObservationIndex, run
from engine.rules import load_rules_from_dir
from pathlib import Path

URL = "https://example.test/"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "redirects"


def scheduler():
    from engine.scheduler import Budgets, Scheduler

    instance = Scheduler(Budgets(per_host_interval=0.001), scope=lambda url: True)
    instance.start()
    return instance


def transport_of(body, status=200, headers=None):
    def transport(url, method, timeout):
        return status, list((headers or {"content-type": "text/html"}).items()), body.encode()

    return transport


def collect(body, **kwargs):
    return redirects.collect(URL, scheduler(), transport=transport_of(body, **kwargs))


class TestMetaRefresh(unittest.TestCase):

    def test_internal_refresh_is_detected(self):
        observation = collect('<meta http-equiv="refresh" content="0; url=/other">')
        self.assertFalse(observation.data["meta_refresh"]["external"])

    def test_external_refresh_is_detected(self):
        observation = collect('<meta http-equiv="refresh" content="0; url=https://evil.test/">')
        self.assertTrue(observation.data["meta_refresh"]["external"])

    def test_destination_is_absolute(self):
        observation = collect('<meta http-equiv="refresh" content="0; url=/other">')
        self.assertEqual(observation.data["meta_refresh"]["destination"], "https://example.test/other")

    def test_absent_refresh_is_none(self):
        self.assertIsNone(collect("<p>no meta</p>").data["meta_refresh"])

    def test_refresh_without_url_is_none(self):
        self.assertIsNone(collect('<meta http-equiv="refresh" content="5">').data["meta_refresh"])


class TestJsRedirect(unittest.TestCase):

    def test_location_assignment_is_detected(self):
        observation = collect('<script>location.href = "/next";</script>')
        self.assertEqual(observation.data["js_redirect"]["destination"], "https://example.test/next")

    def test_external_target_is_flagged(self):
        observation = collect('<script>location.replace("https://evil.test/");</script>')
        self.assertTrue(observation.data["js_redirect"]["external"])

    def test_absent_script_is_none(self):
        self.assertIsNone(collect("<p>no script</p>").data["js_redirect"])


class TestRules(unittest.TestCase):

    def ids(self, observation):
        normal, low = run(load_rules_from_dir(RULES_DIR), [observation],
                          satisfied=frozenset({"proof", "consent"}))
        return sorted(f.rule_id for f in normal + low)

    def test_external_meta_fires_low(self):
        self.assertEqual(self.ids(collect('<meta http-equiv="refresh" content="0; url=https://evil.test/">')),
                         ["redirects.meta-refresh-external"])

    def test_internal_meta_fires_info(self):
        self.assertEqual(self.ids(collect('<meta http-equiv="refresh" content="0; url=/other">')),
                         ["redirects.meta-refresh-internal"])

    def test_external_js_fires_low(self):
        self.assertEqual(self.ids(collect('<script>location.href = "https://evil.test/";</script>')),
                         ["redirects.js-redirect-external"])

    def test_plain_page_fires_nothing(self):
        self.assertEqual(self.ids(collect("<p>nothing</p>")), [])


if __name__ == "__main__":
    unittest.main()