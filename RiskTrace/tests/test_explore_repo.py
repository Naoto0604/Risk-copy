import unittest

import requests

from collectors.explore import repo
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
    return repo.collect(
        URL,
        kwargs.pop("sched", None) or scheduler(),
        transport=transport_from(table or {}),
    )


class TestExposure(unittest.TestCase):

    def test_exposed_head_is_recorded(self):
        observation = collect({URL + ".git/HEAD": text("ref: refs/heads/main\n")})
        self.assertTrue(observation.data["exposed"])
        self.assertEqual(observation.data["paths"][0]["outcome"], "found")

    def test_branch_is_extracted(self):
        observation = collect({URL + ".git/HEAD": text("ref: refs/heads/main\n")})
        self.assertEqual(observation.data["head_branch"], "refs/heads/main")
        self.assertFalse(observation.data["head_detached"])

    def test_detached_head_is_flagged(self):
        sha = "a" * 40
        observation = collect({URL + ".git/HEAD": text(sha + "\n")})
        self.assertTrue(observation.data["head_detached"])
        self.assertIsNone(observation.data["head_branch"])

    def test_missing_git_is_not_exposed(self):
        observation = collect({})
        self.assertFalse(observation.data["exposed"])
        self.assertEqual(observation.data["paths"][0]["outcome"], "absent")

    def test_gated_git_is_not_exposed(self):
        observation = collect({URL + ".git/HEAD": text("", status=403)})
        self.assertFalse(observation.data["exposed"])
        self.assertEqual(observation.data["paths"][0]["outcome"], "gated")

    def test_directory_listing_is_recorded(self):
        observation = collect({URL + ".git/": text('<a href="HEAD">HEAD</a>',
                                                   content_type="text/html")})
        entries = {entry["path"]: entry["outcome"] for entry in observation.data["paths"]}
        self.assertEqual(entries["/.git/"], "found")

    def test_binary_snippet_is_dropped(self):
        observation = collect({URL + ".git/HEAD": text("ref: x", content_type="application/zip")})
        self.assertIsNone(observation.data["paths"][0]["snippet"])


class TestConfig(unittest.TestCase):

    def test_https_remote_is_parsed(self):
        body = '[remote "origin"]\n\turl = https://github.com/org/repo.git\n'
        observation = collect({URL + ".git/config": text(body)})
        remote = observation.data["remotes"][0]
        self.assertEqual(remote["host"], "github.com")
        self.assertEqual(remote["provider"], "github")
        self.assertEqual(observation.data["providers"], ["github"])

    def test_scp_style_remote_host_is_parsed(self):
        body = '[remote "origin"]\n\turl = git@gitlab.com:org/repo.git\n'
        observation = collect({URL + ".git/config": text(body)})
        self.assertEqual(observation.data["remotes"][0]["host"], "gitlab.com")

    def test_credentials_are_masked(self):
        body = '[remote "origin"]\n\turl = https://user:secret@example.test/org/repo.git\n'
        observation = collect({URL + ".git/config": text(body)})
        url = observation.data["remotes"][0]["url"]
        self.assertIn("<masked>@example.test", url)
        self.assertNotIn("secret", url)

    def test_unknown_host_is_other(self):
        body = '[remote "origin"]\n\turl = https://git.internal.test/org/repo.git\n'
        observation = collect({URL + ".git/config": text(body)})
        self.assertEqual(observation.data["remotes"][0]["provider"], "other")

    def test_non_remote_sections_are_ignored(self):
        body = '[core]\n\turl = https://ignored.test/x\n'
        observation = collect({URL + ".git/config": text(body)})
        self.assertEqual(observation.data["remotes"], [])

    def test_parse_config_reads_multiple_remotes(self):
        body = ('[remote "origin"]\n\turl = https://github.com/a/b.git\n'
                '[remote "upstream"]\n\turl = https://github.com/c/d.git\n')
        self.assertEqual(len(repo.parse_config(body)), 2)


class TestControl(unittest.TestCase):

    def test_robots_blocks_a_path(self):
        table = {URL + "robots.txt": text("User-agent: *\nDisallow: /.git/\n")}
        observation = collect(table)
        self.assertEqual(observation.data["paths"], [])
        self.assertEqual(observation.data["skipped"][0]["reason"], "robots")

    def test_fetch_error_is_recorded(self):
        def transport(url, method, timeout):
            if url.endswith("/robots.txt"):
                return 404, [], b""
            raise requests.ConnectionError("boom")

        observation = repo.collect(URL, scheduler(), transport=transport)
        self.assertTrue(observation.is_ok)
        self.assertIn("boom", observation.data["paths"][0]["error"])

    def test_budget_exhaustion_truncates_without_raising(self):
        observation = collect(
            {},
            sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        sched = scheduler()
        sched.cancel("test")
        with self.assertRaises(Cancelled):
            repo.collect(URL, sched, transport=transport_from({}))

    def test_invalid_target_is_an_error(self):
        observation = repo.collect("ftp://x", scheduler(), transport=transport_from({}))
        self.assertTrue(observation.is_error)

    def test_no_verdict_is_recorded(self):
        observation = collect({})
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)


if __name__ == "__main__":
    unittest.main()