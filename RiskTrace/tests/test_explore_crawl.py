import unittest

import requests

from collectors.explore import crawl
from engine.scheduler import Budgets, Cancelled, Scheduler


def scheduler(scope=None, budgets=None):
    instance = Scheduler(
        budgets or Budgets(per_host_interval=0.001),
        scope=scope or (lambda url: True),
    )
    instance.start()
    return instance


def html(*links):
    body = "".join(f'<a href="{link}">link</a>' for link in links)
    return 200, [("Content-Type", "text/html; charset=utf-8")], body.encode()


def plain(body, status=200, content_type="text/plain"):
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


def collect(start, table=None, **kwargs):
    return crawl.collect(
        start,
        kwargs.pop("sched", None) or scheduler(),
        transport=transport_from(table or {}),
        **kwargs,
    )


class TestNormalize(unittest.TestCase):

    def test_fragment_is_dropped(self):
        self.assertEqual(
            crawl.normalize_url("https://example.test/a#top"),
            "https://example.test/a",
        )

    def test_query_is_kept(self):
        self.assertEqual(
            crawl.normalize_url("https://example.test/s?q=1"),
            "https://example.test/s?q=1",
        )

    def test_scheme_and_host_are_lowercased(self):
        self.assertEqual(
            crawl.normalize_url("HTTPS://Example.TEST/a"),
            "https://example.test/a",
        )

    def test_empty_path_becomes_root(self):
        self.assertEqual(crawl.normalize_url("https://example.test"), "https://example.test/")

    def test_unsupported_scheme_is_rejected(self):
        self.assertIsNone(crawl.normalize_url("ftp://example.test/"))

    def test_credentials_are_rejected(self):
        self.assertIsNone(crawl.normalize_url("https://u:p@example.test/"))


class TestRobots(unittest.TestCase):

    def test_wildcard_group_is_used(self):
        rules = crawl.parse_robots("User-agent: *\nDisallow: /private\n")
        self.assertEqual(rules, (("/private", False),))

    def test_own_agent_takes_precedence(self):
        rules = crawl.parse_robots(
            "User-agent: *\nDisallow: /\n\nUser-agent: RiskTrace\nAllow: /\n"
        )
        self.assertEqual(rules, (("/", True),))

    def test_longest_match_wins(self):
        robots = crawl._Robots((("/private", False), ("/private/ok", True)), "fetched")
        self.assertFalse(robots.allows("/private/x"))
        self.assertTrue(robots.allows("/private/ok"))

    def test_wildcard_pattern_matches(self):
        robots = crawl._Robots((("/*.pdf$", False),), "fetched")
        self.assertFalse(robots.allows("/doc.pdf"))
        self.assertTrue(robots.allows("/doc.pdf.html"))

    def test_empty_rule_set_allows_everything(self):
        self.assertTrue(crawl._Robots().allows("/anything"))


class TestCrawl(unittest.TestCase):

    def test_root_is_fetched(self):
        observation = collect("https://example.test/", {"https://example.test/": html()})
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["urls"], ["https://example.test/"])

    def test_links_are_followed_within_depth(self):
        table = {
            "https://example.test/": html("/a"),
            "https://example.test/a": html("/b"),
            "https://example.test/b": html("/c"),
        }
        observation = collect("https://example.test/", table)
        self.assertEqual(
            observation.data["urls"],
            ["https://example.test/", "https://example.test/a", "https://example.test/b"],
        )

    def test_depth_zero_fetches_only_root(self):
        table = {"https://example.test/": html("/a"), "https://example.test/a": html()}
        observation = collect("https://example.test/", table, max_depth=0)
        self.assertEqual(observation.data["urls"], ["https://example.test/"])

    def test_page_limit_truncates(self):
        table = {"https://example.test/": html("/a", "/b"), "https://example.test/a": html()}
        observation = collect("https://example.test/", table, max_pages=1)
        self.assertEqual(len(observation.data["urls"]), 1)
        self.assertTrue(observation.data["truncated"])
        self.assertEqual(observation.data["truncated_reason"], "pages")
        self.assertIn("ページ上限", observation.note)

    def test_page_limit_is_capped(self):
        observation = collect("https://example.test/", {"https://example.test/": html()}, max_pages=999)
        self.assertEqual(observation.data["max_pages"], crawl.MAX_PAGES_HARD)

    def test_external_host_is_not_followed(self):
        table = {"https://example.test/": html("https://other.test/x")}
        observation = collect("https://example.test/", table)
        self.assertEqual(observation.data["urls"], ["https://example.test/"])
        self.assertEqual(observation.data["skipped"][0]["reason"], "out_of_scope")

    def test_other_port_is_not_followed(self):
        table = {"https://example.test/": html("https://example.test:8443/x")}
        observation = collect("https://example.test/", table)
        self.assertEqual(observation.data["urls"], ["https://example.test/"])

    def test_scheme_change_is_not_followed(self):
        table = {"https://example.test/": html("http://example.test/x")}
        observation = collect("https://example.test/", table)
        self.assertEqual(observation.data["urls"], ["https://example.test/"])

    def test_scope_denial_skips_the_link(self):
        table = {"https://example.test/": html("/a", "/b")}
        observation = collect(
            "https://example.test/",
            table,
            sched=scheduler(scope=lambda url: not url.endswith("/b")),
        )
        self.assertIn("https://example.test/a", observation.data["urls"])
        reasons = {entry["url"]: entry["reason"] for entry in observation.data["skipped"]}
        self.assertEqual(reasons["https://example.test/b"], "out_of_scope")

    def test_robots_out_of_scope_is_not_fatal(self):
        table = {"https://example.test/": html()}
        observation = collect(
            "https://example.test/",
            table,
            sched=scheduler(scope=lambda url: "/robots.txt" not in url),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["robots"], "unavailable")

    def test_duplicate_fragments_are_fetched_once(self):
        table = {"https://example.test/": html("/a#one", "/a#two"), "https://example.test/a": html()}
        observation = collect("https://example.test/", table)
        self.assertEqual(observation.data["urls"].count("https://example.test/a"), 1)

    def test_query_variants_are_distinct(self):
        table = {
            "https://example.test/": html("/s?q=1", "/s?q=2"),
            "https://example.test/s?q=1": html(),
            "https://example.test/s?q=2": html(),
        }
        observation = collect("https://example.test/", table)
        self.assertIn("https://example.test/s?q=1", observation.data["urls"])
        self.assertIn("https://example.test/s?q=2", observation.data["urls"])

    def test_non_html_is_recorded_but_not_parsed(self):
        table = {
            "https://example.test/": html("/style.css"),
            "https://example.test/style.css": plain('<a href="/inner">x</a>', content_type="text/css"),
        }
        observation = collect("https://example.test/", table)
        self.assertIn("https://example.test/style.css", observation.data["urls"])
        self.assertNotIn("https://example.test/inner", observation.data["urls"])

    def test_mailto_and_javascript_are_ignored(self):
        table = {"https://example.test/": html("mailto:a@example.test", "javascript:void(0)")}
        observation = collect("https://example.test/", table)
        self.assertEqual(observation.data["urls"], ["https://example.test/"])

    def test_robots_disallow_blocks_a_path(self):
        table = {
            "https://example.test/robots.txt": plain("User-agent: *\nDisallow: /private\n"),
            "https://example.test/": html("/private/x", "/ok"),
            "https://example.test/ok": html(),
        }
        observation = collect("https://example.test/", table)
        self.assertIn("https://example.test/ok", observation.data["urls"])
        self.assertNotIn("https://example.test/private/x", observation.data["urls"])

    def test_robots_allow_overrides_disallow(self):
        table = {
            "https://example.test/robots.txt": plain(
                "User-agent: *\nDisallow: /private\nAllow: /private/ok\n"
            ),
            "https://example.test/": html("/private/ok"),
            "https://example.test/private/ok": html(),
        }
        observation = collect("https://example.test/", table)
        self.assertIn("https://example.test/private/ok", observation.data["urls"])

    def test_unavailable_robots_allows_everything(self):
        table = {"https://example.test/": html("/a"), "https://example.test/a": html()}
        observation = collect("https://example.test/", table)
        self.assertEqual(observation.data["robots"], "unavailable")
        self.assertIn("https://example.test/a", observation.data["urls"])

    def test_fetch_failure_is_recorded_and_crawl_continues(self):
        def transport(url, method, timeout):
            if url.endswith("/broken"):
                raise requests.ConnectionError("boom")
            if url.endswith("/robots.txt"):
                return 404, [], b""
            return html("/broken", "/ok")

        observation = crawl.collect(
            "https://example.test/", scheduler(), transport=transport
        )
        self.assertTrue(observation.is_ok)
        broken = [page for page in observation.data["pages"] if page["url"].endswith("/broken")]
        self.assertEqual(len(broken), 1)
        self.assertIn("error", broken[0])
        self.assertIn("https://example.test/ok", observation.data["urls"])

    def test_budget_exhaustion_truncates_without_raising(self):
        table = {"https://example.test/": html("/a")}
        observation = collect(
            "https://example.test/",
            table,
            sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        sched = scheduler()
        sched.cancel("test")
        with self.assertRaises(Cancelled):
            crawl.collect("https://example.test/", sched, transport=transport_from({}))


class TestControl(unittest.TestCase):

    def test_robots_costs_one_request(self):
        sched = scheduler()
        crawl.collect("https://example.test/", sched, transport=transport_from({"https://example.test/": html()}))
        self.assertEqual(sched.usage()["request"], 2)

    def test_each_page_costs_one_request(self):
        table = {
            "https://example.test/": html("/a", "/b"),
            "https://example.test/a": html(),
            "https://example.test/b": html(),
        }
        sched = scheduler()
        crawl.collect("https://example.test/", sched, transport=transport_from(table))
        self.assertEqual(sched.usage()["request"], 4)

    def test_subject_is_the_normalized_start(self):
        observation = collect("HTTPS://Example.TEST", {"https://example.test/": html()})
        self.assertEqual(observation.subject, "https://example.test/")

    def test_invalid_start_is_an_error_observation(self):
        observation = collect("ftp://example.test/")
        self.assertTrue(observation.is_error)

    def test_no_verdict_is_recorded(self):
        observation = collect("https://example.test/", {"https://example.test/": html()})
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)

    def test_redirect_target_becomes_the_subject(self):
        table = {
            "https://example.test/": (301, [("Location", "https://example.test/home")], b""),
            "https://example.test/home": html(),
        }
        observation = collect("https://example.test/", table)
        self.assertIn("https://example.test/home", observation.data["urls"])
        self.assertEqual(observation.data["pages"][0]["redirected_from"], "https://example.test/")


if __name__ == "__main__":
    unittest.main()