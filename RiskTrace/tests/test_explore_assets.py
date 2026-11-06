import unittest

import requests

from collectors.explore import assets
from engine.scheduler import Budgets, Cancelled, Scheduler

URL = "https://example.test/"


def scheduler(scope=None, budgets=None):
    instance = Scheduler(
        budgets or Budgets(per_host_interval=0.001),
        scope=scope or (lambda url: True),
    )
    instance.start()
    return instance


def page(body, status=200, content_type="text/html; charset=utf-8"):
    return status, [("Content-Type", content_type)], body.encode()


def transport_from(table):
    calls = []

    def transport(url, method, timeout):
        calls.append(url)
        reply = table.get(url)
        if reply is None:
            return 404, [("Content-Type", "text/html")], b"missing"
        status, headers, body = reply
        return status, headers, body

    transport.calls = calls
    return transport


def collect(table=None, urls=(URL,), **kwargs):
    return assets.collect(
        list(urls),
        kwargs.pop("sched", None) or scheduler(),
        transport=transport_from(table or {}),
        **kwargs,
    )


class TestExtract(unittest.TestCase):

    def test_script_src_is_found(self):
        found, unresolved = assets.extract_assets(
            '<script src="/app.js"></script>', URL
        )
        self.assertEqual([asset["url"] for asset in found], [URL + "app.js"])
        self.assertEqual(unresolved, 0)

    def test_srcset_yields_every_candidate(self):
        found, _ = assets.extract_assets(
            '<img srcset="/a.png 1x, /b.png 2x">', URL
        )
        self.assertEqual([asset["url"] for asset in found], [URL + "a.png", URL + "b.png"])

    def test_protocol_relative_is_resolved(self):
        found, _ = assets.extract_assets('<script src="//cdn.test/x.js"></script>', URL)
        self.assertEqual(found[0]["url"], "https://cdn.test/x.js")

    def test_data_uri_counts_as_unresolved(self):
        found, unresolved = assets.extract_assets(
            '<img src="data:image/png;base64,AAAA">', URL
        )
        self.assertEqual(found, [])
        self.assertEqual(unresolved, 1)

    def test_integrity_is_recorded_for_scripts(self):
        found, _ = assets.extract_assets(
            '<script src="/a.js" integrity="sha384-x" crossorigin></script>', URL
        )
        self.assertTrue(found[0]["integrity"])
        self.assertTrue(found[0]["crossorigin"])

    def test_missing_integrity_is_false_not_none(self):
        found, _ = assets.extract_assets('<script src="/a.js"></script>', URL)
        self.assertFalse(found[0]["integrity"])

    def test_integrity_is_none_for_images(self):
        found, _ = assets.extract_assets('<img src="/a.png">', URL)
        self.assertIsNone(found[0]["integrity"])

    def test_empty_attribute_is_ignored(self):
        found, _ = assets.extract_assets('<script src=""></script>', URL)
        self.assertEqual(found, [])


class TestCollect(unittest.TestCase):

    def test_same_origin_asset_is_classified_as_same(self):
        observation = collect({URL: page('<script src="/a.js"></script>')})
        asset = observation.data["pages"][0]["assets"][0]
        self.assertEqual(asset["kind"], "same")
        self.assertEqual(observation.data["external_hosts"], [])

    def test_external_asset_is_classified_and_hosted(self):
        observation = collect({URL: page('<script src="https://cdn.test/a.js"></script>')})
        asset = observation.data["pages"][0]["assets"][0]
        self.assertEqual(asset["kind"], "external")
        self.assertEqual(observation.data["external_hosts"], ["cdn.test"])

    def test_external_host_is_listed_once(self):
        body = ('<script src="https://cdn.test/a.js"></script>'
                '<script src="https://cdn.test/b.js"></script>')
        observation = collect({URL: page(body)})
        self.assertEqual(observation.data["external_hosts"], ["cdn.test"])

    def test_counts_are_summarised(self):
        body = '<script src="/a.js"></script><script src="https://cdn.test/b.js"></script>'
        observation = collect({URL: page(body)})
        counts = observation.data["pages"][0]["counts"]
        self.assertEqual(counts["same"], 1)
        self.assertEqual(counts["external"], 1)
        self.assertEqual(counts["without_integrity"], 2)

    def test_non_html_page_is_skipped(self):
        observation = collect({URL: page("body{}", content_type="text/css")})
        self.assertEqual(observation.data["pages"], [])
        self.assertEqual(observation.data["skipped"][0]["reason"], "non_html")

    def test_duplicate_targets_are_fetched_once(self):
        transport = transport_from({URL: page("")})
        assets.collect([URL, URL + "#x"], scheduler(), transport=transport)
        self.assertEqual(transport.calls.count(URL), 1)

    def test_page_limit_truncates(self):
        table = {URL: page(""), URL + "a": page("")}
        observation = collect(table, urls=(URL, URL + "a"), max_pages=1)
        self.assertEqual(observation.data["truncated_reason"], "pages")

    def test_page_limit_is_capped(self):
        observation = collect({URL: page("")}, max_pages=999)
        self.assertEqual(observation.data["max_pages"], assets.MAX_PAGES_HARD)

    def test_robots_blocks_a_page(self):
        table = {URL + "robots.txt": page("User-agent: *\nDisallow: /a\n"),
                 URL: page(""), URL + "a": page("")}
        observation = collect(table, urls=(URL, URL + "a"))
        self.assertEqual(len(observation.data["pages"]), 1)
        self.assertEqual(observation.data["skipped"][0]["reason"], "robots")

    def test_fetch_error_is_recorded(self):
        def transport(url, method, timeout):
            if url.endswith("/robots.txt"):
                return 404, [], b""
            raise requests.ConnectionError("boom")

        observation = assets.collect([URL], scheduler(), transport=transport)
        self.assertTrue(observation.is_ok)
        self.assertIn("boom", observation.data["pages"][0]["error"])

    def test_budget_exhaustion_truncates_without_raising(self):
        observation = collect({URL: page("")},
                              sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)))
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        sched = scheduler()
        sched.cancel("test")
        with self.assertRaises(Cancelled):
            assets.collect([URL], sched, transport=transport_from({}))


class TestControl(unittest.TestCase):

    def test_empty_input_is_an_error(self):
        observation = assets.collect([], scheduler(), transport=transport_from({}))
        self.assertTrue(observation.is_error)

    def test_invalid_urls_only_is_an_error(self):
        observation = assets.collect(["ftp://x"], scheduler(), transport=transport_from({}))
        self.assertTrue(observation.is_error)

    def test_subject_is_the_first_target(self):
        observation = collect({URL: page("")})
        self.assertEqual(observation.subject, URL)

    def test_no_verdict_is_recorded(self):
        observation = collect({URL: page('<script src="/a.js"></script>')})
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)


if __name__ == "__main__":
    unittest.main()