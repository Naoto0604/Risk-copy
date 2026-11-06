import unittest

import requests

from collectors.explore import discover
from engine.scheduler import Budgets, Cancelled, Scheduler

URL = "https://example.test/"


def scheduler(scope=None, budgets=None):
    instance = Scheduler(
        budgets or Budgets(per_host_interval=0.001),
        scope=scope or (lambda url: True),
    )
    instance.start()
    return instance


def text(body, status=200, content_type="text/plain"):
    return status, [("Content-Type", content_type)], body.encode()


def sitemap(*locs, index=False):
    tag = "sitemapindex" if index else "urlset"
    body = "".join(f"<sitemap><loc>{loc}</loc></sitemap>" if index
                   else f"<url><loc>{loc}</loc></url>" for loc in locs)
    body = f'<?xml version="1.0"?><{tag}>{body}</{tag}>'
    return 200, [("Content-Type", "application/xml")], body.encode()


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


def collect(table=None, **kwargs):
    return discover.collect(
        URL,
        kwargs.pop("sched", None) or scheduler(),
        transport=transport_from(table or {}),
        **kwargs,
    )


class TestSitemap(unittest.TestCase):

    def test_locs_are_collected(self):
        table = {URL + "sitemap.xml": sitemap(URL + "a", URL + "b")}
        observation = collect(table, paths=())
        self.assertEqual(observation.data["urls"], [URL + "a", URL + "b"])

    def test_robots_sitemap_line_is_followed(self):
        table = {
            URL + "robots.txt": text(f"Sitemap: {URL}extra.xml\n"),
            URL + "extra.xml": sitemap(URL + "from-robots"),
        }
        observation = collect(table, paths=())
        self.assertIn(URL + "from-robots", observation.data["urls"])

    def test_sitemap_index_is_expanded_once(self):
        table = {
            URL + "sitemap.xml": sitemap(URL + "child.xml", index=True),
            URL + "child.xml": sitemap(URL + "deep"),
        }
        observation = collect(table, paths=())
        self.assertIn(URL + "deep", observation.data["urls"])

    def test_sitemap_count_is_capped(self):
        table = {
            URL + "sitemap.xml": sitemap(*[URL + f"c{i}.xml" for i in range(10)], index=True),
        }
        observation = collect(table, paths=())
        self.assertEqual(observation.data["truncated_reason"], "sitemaps")

    def test_external_loc_is_skipped(self):
        table = {URL + "sitemap.xml": sitemap("https://other.test/x")}
        observation = collect(table, paths=())
        self.assertEqual(observation.data["urls"], [])
        self.assertEqual(observation.data["skipped"][0]["reason"], "out_of_scope")

    def test_robots_disallowed_loc_is_skipped(self):
        table = {
            URL + "robots.txt": text("User-agent: *\nDisallow: /private\n"),
            URL + "sitemap.xml": sitemap(URL + "private/x", URL + "ok"),
        }
        observation = collect(table, paths=())
        self.assertEqual(observation.data["urls"], [URL + "ok"])

    def test_broken_xml_does_not_fail_the_observation(self):
        table = {URL + "sitemap.xml": text("<urlset><url>", content_type="application/xml")}
        observation = collect(table, paths=())
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["urls"], [])

    def test_missing_sitemap_is_recorded_with_status(self):
        observation = collect({}, paths=())
        self.assertEqual(observation.data["sitemaps"][0]["status"], 404)

    def test_sitemap_fetch_error_is_recorded(self):
        def transport(url, method, timeout):
            raise requests.ConnectionError("boom")

        observation = discover.collect(URL, scheduler(), transport=transport, paths=())
        self.assertTrue(observation.is_ok)
        self.assertIn("boom", observation.data["sitemaps"][0]["error"])

    def test_sitemap_can_be_disabled(self):
        table = {URL + "sitemap.xml": sitemap(URL + "a")}
        observation = collect(table, paths=(), include_sitemap=False)
        self.assertEqual(observation.data["sitemaps"], [])


class TestProbes(unittest.TestCase):

    def test_found_path(self):
        observation = collect({URL + "admin": text("<html>admin</html>", content_type="text/html")},
                              paths=("/admin",))
        self.assertEqual(observation.data["probes"][0]["outcome"], "found")

    def test_gated_path(self):
        observation = collect({URL + "admin": text("", status=403)}, paths=("/admin",))
        self.assertEqual(observation.data["probes"][0]["outcome"], "gated")

    def test_absent_path(self):
        observation = collect({}, paths=("/admin",))
        self.assertEqual(observation.data["probes"][0]["outcome"], "absent")

    def test_other_status_is_not_called_found(self):
        observation = collect({URL + "api": text("", status=500)}, paths=("/api",))
        self.assertEqual(observation.data["probes"][0]["outcome"], "other")
        self.assertNotIn(URL + "api", observation.data["found"])

    def test_prefix_is_kept_for_text(self):
        observation = collect({URL + ".git/HEAD": text("ref: refs/heads/main\n")},
                              paths=("/.git/HEAD",))
        self.assertEqual(observation.data["probes"][0]["prefix"], "ref: refs/heads/main")

    def test_prefix_is_dropped_for_binary(self):
        observation = collect({URL + "backup.zip": text("PK", content_type="application/zip")},
                              paths=("/backup.zip",))
        self.assertIsNone(observation.data["probes"][0]["prefix"])

    def test_gated_paths_are_listed_as_found(self):
        observation = collect({URL + "admin": text("", status=401)}, paths=("/admin",))
        self.assertIn(URL + "admin", observation.data["found"])

    def test_robots_blocks_a_probe(self):
        table = {URL + "robots.txt": text("User-agent: *\nDisallow: /admin\n")}
        observation = collect(table, paths=("/admin",))
        self.assertEqual(observation.data["probes"], [])
        self.assertEqual(observation.data["skipped"][0]["reason"], "robots")

    def test_paths_are_capped(self):
        observation = collect({}, paths=tuple(f"/p{i}" for i in range(100)))
        self.assertEqual(len(observation.data["probes"]), discover.MAX_PROBES)

    def test_probe_error_is_recorded(self):
        def transport(url, method, timeout):
            if url.endswith("/admin"):
                raise requests.ConnectionError("boom")
            return 404, [], b""

        observation = discover.collect(URL, scheduler(), transport=transport, paths=("/admin",))
        self.assertEqual(observation.data["probes"][0]["outcome"], "error")


class TestControl(unittest.TestCase):

    def test_subject_is_the_normalized_start(self):
        observation = discover.collect("HTTPS://Example.TEST", scheduler(),
                                       transport=transport_from({}), paths=())
        self.assertEqual(observation.subject, URL)

    def test_invalid_start_is_an_error_observation(self):
        observation = discover.collect("ftp://example.test/", scheduler(),
                                       transport=transport_from({}), paths=())
        self.assertTrue(observation.is_error)

    def test_no_verdict_is_recorded(self):
        observation = collect({URL + "admin": text("ok")}, paths=("/admin",))
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)

    def test_budget_exhaustion_truncates_without_raising(self):
        observation = collect({}, paths=("/admin", "/api"),
                              sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)))
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        sched = scheduler()
        sched.cancel("test")
        with self.assertRaises(Cancelled):
            discover.collect(URL, sched, transport=transport_from({}), paths=())


if __name__ == "__main__":
    unittest.main()