import unittest

from engine.legacy_crawl import crawl_urls, normalize_url

HTML = {"content-type": "text/html; charset=utf-8"}


def page(html="", status=200, headers=None):
    return (status, list((headers or HTML).items()), html.encode("utf-8"))


def transport_of(pages):
    """url -> 応答 の表から transport を作る。"""
    calls = []

    def transport(url, method, timeout):
        calls.append(url)
        if url in pages:
            return pages[url]
        return page("<p>ok</p>")

    transport.calls = calls
    return transport


class TestNormalize(unittest.TestCase):

    def test_unicode_and_encoded_forms_match(self):
        unicode_url = "https://example.com/contact/?topic=日本語"
        encoded_url = "https://example.com/contact/?topic=%E6%97%A5%E6%9C%AC%E8%AA%9E#part"
        self.assertEqual(normalize_url(unicode_url), normalize_url(encoded_url))

    def test_duplicate_query_keys_are_kept(self):
        self.assertEqual(
            normalize_url("https://example.com/?a=1&a=2"),
            "https://example.com/?a=1&a=2",
        )

    def test_query_values_are_distinguished(self):
        self.assertNotEqual(
            normalize_url("https://example.com/?topic=food"),
            normalize_url("https://example.com/?topic=fashion"),
        )

    def test_credentials_are_rejected(self):
        self.assertIsNone(normalize_url("https://u:p@example.com/"))

    def test_non_http_scheme_is_rejected(self):
        self.assertIsNone(normalize_url("ftp://example.com/"))


class TestCrawl(unittest.TestCase):

    def test_bad_start_url_raises(self):
        with self.assertRaises(ValueError):
            crawl_urls("not a url")

    def test_external_link_is_not_crawled(self):
        transport = transport_of({
            "http://example.com/": page(
                '<a href="/inside">内部</a><a href="http://evil.example/">外部</a>'
            ),
        })
        result = crawl_urls("http://example.com/", max_pages=10, transport=transport)
        self.assertEqual(result, {"http://example.com/", "http://example.com/inside"})

    def test_other_port_is_not_crawled(self):
        transport = transport_of({
            "http://example.com/": page('<a href="http://example.com:8000/">別ポート</a>'),
        })
        result = crawl_urls("http://example.com/", max_pages=10, transport=transport)
        self.assertEqual(result, {"http://example.com/"})

    def test_max_pages_is_respected(self):
        links = "".join(f'<a href="/p{i}">x</a>' for i in range(10))
        transport = transport_of({"http://example.com/": page(links)})
        result = crawl_urls("http://example.com/", max_pages=4, transport=transport)
        self.assertEqual(len(result), 4)
        self.assertTrue(transport.calls[0].endswith("/robots.txt"))
        self.assertEqual(len(transport.calls), 5)

    def test_duplicate_link_forms_are_visited_once(self):
        transport = transport_of({
            "http://example.com/": page(
                '<a href="/contact/?topic=日本語">a</a>'
                '<a href="/contact/?topic=%E6%97%A5%E6%9C%AC%E8%AA%9E#f">b</a>'
            ),
        })
        result = crawl_urls("http://example.com/", max_pages=10, transport=transport)
        self.assertEqual(
            result,
            {"http://example.com/", "http://example.com/contact/?topic=%E6%97%A5%E6%9C%AC%E8%AA%9E"},
        )

    def test_fetch_error_page_is_not_counted(self):
        transport = transport_of({})
        result = crawl_urls("http://example.com/", max_pages=10, transport=transport)
        self.assertEqual(result, {"http://example.com/"})


if __name__ == "__main__":
    unittest.main()