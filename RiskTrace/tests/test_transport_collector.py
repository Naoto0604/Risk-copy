import unittest

from collectors.http.transport import collect


class TestTransportCollector(unittest.TestCase):

    def test_http_scheme_is_observed(self):
        observation = collect("http://example.test/path")
        self.assertEqual(observation.collector, "http_transport")
        self.assertEqual(observation.data["scheme"], "http")

    def test_https_scheme_is_observed(self):
        self.assertEqual(collect("https://example.test/").data["scheme"], "https")

    def test_scheme_is_lowercased(self):
        self.assertEqual(collect("HTTPS://example.test/").data["scheme"], "https")

    def test_other_scheme_is_an_error(self):
        self.assertTrue(collect("ftp://example.test/").is_error)


if __name__ == "__main__":
    unittest.main()