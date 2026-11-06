import unittest

from collectors.http import cookies
from engine.scheduler import Budgets, Scheduler


def scheduler():
    instance = Scheduler(Budgets(per_host_interval=0.001))
    instance.start()
    return instance


def transport_with(*set_cookie_values, url_status=200):
    def transport(url, method, timeout):
        headers = [("Set-Cookie", value) for value in set_cookie_values]
        return url_status, headers, b""

    return transport


def collect(*values, url="https://example.test/", **kwargs):
    return cookies.collect(url, scheduler(), transport=transport_with(*values, **kwargs))


class TestNoCookies(unittest.TestCase):

    def test_no_header_yields_zero(self):
        observation = collect()
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["count"], 0)

    def test_empty_list_is_returned(self):
        self.assertEqual(collect().data["cookies"], [])


class TestAttributes(unittest.TestCase):

    def test_full_set_cookie_is_observed(self):
        observation = collect("session=abc; HttpOnly; Secure; SameSite=Lax")
        attributes = observation.data["cookies"][0]["attributes"]
        self.assertTrue(attributes["httponly"])
        self.assertTrue(attributes["secure"])
        self.assertEqual(observation.data["cookies"][0]["samesite"], "lax")

    def test_missing_attributes_are_false(self):
        observation = collect("theme=dark")
        attributes = observation.data["cookies"][0]["attributes"]
        self.assertFalse(attributes["httponly"])
        self.assertFalse(attributes["secure"])
        self.assertFalse(attributes["samesite"])

    def test_attribute_names_require_exact_match(self):
        observation = collect("session=notsecure; xhttponly=true; SameSite=Lax")
        attributes = observation.data["cookies"][0]["attributes"]
        self.assertFalse(attributes["httponly"])
        self.assertFalse(attributes["secure"])

    def test_attribute_matching_is_case_insensitive(self):
        observation = collect("session=abc; hTtPoNlY; sEcUrE")
        attributes = observation.data["cookies"][0]["attributes"]
        self.assertTrue(attributes["httponly"])
        self.assertTrue(attributes["secure"])

    def test_domain_and_path_presence(self):
        observation = collect("session=abc; Domain=private.example; Path=/account")
        attributes = observation.data["cookies"][0]["attributes"]
        self.assertTrue(attributes["domain"])
        self.assertTrue(attributes["path"])

    def test_max_age_and_expires_are_distinguished(self):
        observation = collect("session=abc; Max-Age=3600")
        attributes = observation.data["cookies"][0]["attributes"]
        self.assertTrue(attributes["max-age"])
        self.assertFalse(attributes["expires"])


class TestSamesite(unittest.TestCase):

    def test_valid_values_are_flagged_valid(self):
        for value in ("Lax", "Strict", "None"):
            with self.subTest(value=value):
                cookie = collect(f"c=1; Secure; SameSite={value}").data["cookies"][0]
                self.assertEqual(cookie["samesite"], value.lower())
                self.assertTrue(cookie["samesite_valid"])

    def test_invalid_value_is_flagged_invalid(self):
        cookie = collect("c=1; SameSite=InvalidSecret").data["cookies"][0]
        self.assertEqual(cookie["samesite"], "invalidsecret")
        self.assertFalse(cookie["samesite_valid"])

    def test_absent_samesite_is_none(self):
        self.assertIsNone(collect("c=1").data["cookies"][0]["samesite"])


class TestIdentity(unittest.TestCase):

    def test_cookies_are_numbered(self):
        observation = collect("a=1", "b=2")
        self.assertEqual(
            [cookie["id"] for cookie in observation.data["cookies"]],
            ["Cookie #1", "Cookie #2"],
        )

    def test_multiple_cookies_are_independent(self):
        observation = collect("session=abc; HttpOnly; Secure", "theme=dark")
        first, second = observation.data["cookies"]
        self.assertTrue(first["attributes"]["httponly"])
        self.assertFalse(second["attributes"]["httponly"])

    def test_values_and_names_are_not_stored(self):
        observation = collect("access_token=SUPERSECRET")
        rendered = repr(observation.data)
        self.assertNotIn("SUPERSECRET", rendered)
        self.assertNotIn("access_token", rendered)
        self.assertIn("Cookie #1", rendered)


class TestSplitting(unittest.TestCase):

    def test_expires_comma_does_not_split_a_cookie(self):
        observation = collect(
            "analytics=value; Expires=Wed, 21 Oct 2030 07:28:00 GMT; HttpOnly; Secure"
        )
        self.assertEqual(observation.data["count"], 1)

    def test_coalesced_header_splits_after_expires(self):
        observation = collect(
            "session=secret; Expires=Wed, 21 Oct 2030 07:28:00 GMT; HttpOnly, "
            "theme=dark; Path=/; Secure"
        )
        self.assertEqual(observation.data["count"], 2)
        self.assertTrue(observation.data["cookies"][0]["attributes"]["httponly"])
        self.assertFalse(observation.data["cookies"][1]["attributes"]["httponly"])

    def test_split_set_cookie_direct(self):
        parts = cookies.split_set_cookie(["a=1; Expires=Wed, 21 Oct 2030 07:28:00 GMT, b=2"])
        self.assertEqual(len(parts), 2)


class TestTransport(unittest.TestCase):

    def test_secure_transport_is_recorded(self):
        self.assertTrue(collect("c=1").data["secure_transport"])

    def test_http_transport_is_recorded(self):
        self.assertFalse(collect("c=1", url="http://example.test/").data["secure_transport"])

    def test_collector_does_not_decide_severity(self):
        self.assertNotIn("severity", collect("c=1").data)

    def test_fetch_failure_becomes_error(self):
        import requests

        def transport(url, method, timeout):
            raise requests.ConnectionError("boom")

        observation = cookies.collect("https://example.test/", scheduler(), transport=transport)
        self.assertTrue(observation.is_error)


if __name__ == "__main__":
    unittest.main()