import unittest

from engine.attack_path import generate
from engine.rule_runner import Finding

URL = "http://example.test/"


def finding(rule_id, severity="MEDIUM", subject=URL):
    return Finding(
        id=f"fnd_{rule_id}",
        rule_id=rule_id,
        title="t",
        severity=severity,
        confidence="high",
        subject=subject,
        message="m",
        why="w",
        fix="x",
        verify="",
    )


class TestGenerate(unittest.TestCase):

    def test_insecure_transport_with_weak_cookie_makes_a_path(self):
        paths = generate([finding("transport.https-missing", "HIGH"),
                          finding("cookies.over-http", "LOW")])
        self.assertEqual([path.key for path in paths], ["path:insecure-transport-cookie"])

    def test_insecure_transport_with_weak_header_makes_a_path(self):
        paths = generate([finding("transport.https-missing", "HIGH"),
                          finding("headers.csp-missing")])
        self.assertEqual([path.key for path in paths], ["path:insecure-transport-header"])

    def test_both_conditions_make_two_paths(self):
        paths = generate([finding("transport.https-missing", "HIGH"),
                          finding("cookies.over-http", "LOW"),
                          finding("headers.csp-missing")])
        self.assertEqual(len(paths), 2)

    def test_https_only_makes_no_path(self):
        self.assertEqual(generate([finding("transport.https-present", "INFO")]), ())

    def test_different_subjects_are_separate(self):
        paths = generate([
            finding("transport.https-missing", "HIGH", "http://a.test/"),
            finding("transport.https-missing", "HIGH", "http://b.test/"),
            finding("cookies.over-http", "LOW", "http://a.test/"),
        ])
        self.assertEqual([path.subject for path in paths], ["http://a.test/"])

    def test_rule_ids_are_recorded(self):
        path = generate([finding("transport.https-missing", "HIGH"),
                         finding("cookies.over-http", "LOW")])[0]
        self.assertIn("cookies.over-http", path.rule_ids)

    def test_empty_input(self):
        self.assertEqual(generate([]), ())


    def test_trailing_slash_difference_is_absorbed(self):
        paths = generate([
            finding("transport.https-missing", "HIGH", "http://a.test/x/"),
            finding("cookies.over-http", "LOW", "http://a.test/x"),
        ])
        self.assertEqual(len(paths), 1)

if __name__ == "__main__":
    unittest.main()