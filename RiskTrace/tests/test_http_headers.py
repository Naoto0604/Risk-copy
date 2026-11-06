import unittest

from collectors.http import headers
from engine.scheduler import Budgets, Scheduler


def scheduler():
    instance = Scheduler(Budgets(per_host_interval=0.001))
    instance.start()
    return instance


def transport_with(**headers_):
    def transport(url, method, timeout):
        return 200, headers_.items(), b"<html></html>"

    return transport


class TestCollect(unittest.TestCase):

    def test_reports_present_header(self):
        observation = headers.collect(
            "https://example.test/", scheduler(),
            transport=transport_with(**{"X-Frame-Options": "DENY"}),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["headers"]["x-frame-options"], "DENY")

    def test_missing_header_is_none(self):
        observation = headers.collect("https://example.test/", scheduler(), transport=transport_with())
        self.assertIsNone(observation.data["headers"]["strict-transport-security"])

    def test_all_watched_headers_are_reported(self):
        observation = headers.collect("https://example.test/", scheduler(), transport=transport_with())
        self.assertEqual(set(observation.data["headers"]), set(headers.WATCHED))

    def test_collector_does_not_decide_severity(self):
        observation = headers.collect("https://example.test/", scheduler(), transport=transport_with())
        self.assertNotIn("severity", observation.data)

    def test_header_names_are_lowercased(self):
        observation = headers.collect(
            "https://example.test/", scheduler(),
            transport=transport_with(**{"Content-Security-Policy": "default-src 'self'"}),
        )
        self.assertIn("content-security-policy", observation.data["headers"])

    def test_duplicates_are_counted(self):
        def transport(url, method, timeout):
            return 200, [("X-Test", "a"), ("X-Test", "b")], b""

        observation = headers.collect("https://example.test/", scheduler(), transport=transport)
        self.assertEqual(observation.data["duplicates"]["x-test"], 2)

    def test_status_and_content_type_are_recorded(self):
        def transport(url, method, timeout):
            return 200, {"Content-Type": "text/html; charset=utf-8"}.items(), b""

        observation = headers.collect("https://example.test/", scheduler(), transport=transport)
        self.assertEqual(observation.data["status"], 200)
        self.assertIn("text/html", observation.data["content_type"])

    def test_subject_is_the_final_url(self):
        def transport(url, method, timeout):
            if url.endswith("/start"):
                return 302, {"Location": "/end"}.items(), b""
            return 200, {}.items(), b""

        observation = headers.collect("https://example.test/start", scheduler(), transport=transport)
        self.assertEqual(observation.subject, "https://example.test/end")

    def test_fetch_failure_becomes_error_observation(self):
        import requests

        def transport(url, method, timeout):
            raise requests.ConnectionError("boom")

        observation = headers.collect("https://example.test/", scheduler(), transport=transport)
        self.assertTrue(observation.is_error)
        self.assertIn("ConnectionError", observation.note)

    def test_error_observation_keeps_subject(self):
        import requests

        def transport(url, method, timeout):
            raise requests.ConnectionError("boom")

        observation = headers.collect("https://example.test/", scheduler(), transport=transport)
        self.assertEqual(observation.subject, "https://example.test/")

    def test_cookie_values_are_not_leaked(self):
        def transport(url, method, timeout):
            return 200, {"Set-Cookie": "session=SECRET"}.items(), b""

        observation = headers.collect("https://example.test/", scheduler(), transport=transport)
        self.assertEqual(observation.data["headers"].get("set-cookie"), None)


if __name__ == "__main__":
    unittest.main()