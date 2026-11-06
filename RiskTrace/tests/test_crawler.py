import unittest
from unittest.mock import patch

import requests

from scanner.crawler import crawl, normalize_url


def make_response(status_code=200, html="", location=None):
    response = requests.Response()
    response.status_code = status_code
    response._content = html.encode("utf-8")
    response.encoding = "utf-8"
    response.headers["Content-Type"] = "text/html; charset=utf-8"

    if location:
        response.headers["Location"] = location

    return response


class TestCrawler(unittest.TestCase):

    def test_url_normalization_preserves_identity(self):
        unicode_url = "https://example.com/contact/?topic=日本語"
        encoded_url = "https://EXAMPLE.com/contact/?topic=%E6%97%A5%E6%9C%AC%E8%AA%9E#part"
        self.assertEqual(normalize_url(unicode_url), normalize_url(encoded_url))
        self.assertEqual(
            normalize_url("https://example.com/?a=1&a=2"),
            "https://example.com/?a=1&a=2",
        )
        self.assertNotEqual(
            normalize_url("https://example.com/?topic=food"),
            normalize_url("https://example.com/?topic=fashion"),
        )
        mojibake = "https://example.com/?topic=fashionã«ã¤ãã¦"
        self.assertEqual(normalize_url(mojibake), "https://example.com/?topic=fashion%C3%A3%C2%81%C2%AB%C3%A3%C2%81%C2%A4%C3%A3%C2%81%C2%84%C3%A3%C2%81%C2%A6")

    @patch("scanner.crawler.requests.get")
    def test_unicode_links_decode_and_duplicate_forms_crawl_once(self, mock_get):
        mock_get.side_effect = [
            make_response(html=(
                '<a href="/contact/?topic=日本語">unicode</a>'
                '<a href="/contact/?topic=%E6%97%A5%E6%9C%AC%E8%AA%9E#fragment">encoded</a>'
                '<a href="relative">relative</a>'
                '<a href="/contact/?topic=food">food</a>'
                '<a href="/contact/?topic=fashion">fashion</a>'
                '<a href="/contact/#one">frag1</a><a href="/contact/#two">frag2</a>'
                '<a href="http://evil.example/">external</a>'
                '<a href="http://example.com:8000/">port</a>'
                '<a href="http://[broken">bad</a>'
            )),
            *[make_response(html="<p>ok</p>") for _ in range(5)],
        ]
        result = crawl("http://example.com/", max_pages=4)
        self.assertEqual(len(result), 4)
        self.assertEqual(mock_get.call_count, 4)
        self.assertIn("http://example.com/contact/?topic=%E6%97%A5%E6%9C%AC%E8%AA%9E", result)
        self.assertIn("http://example.com/relative", result)

    @patch("scanner.crawler.requests.get")
    def test_meta_charset_is_used_when_header_omits_charset(self, mock_get):
        response = requests.Response()
        response.status_code = 200
        response._content = (
            '<meta charset="shift_jis"><a href="/日本語">リンク</a>'.encode("shift_jis")
        )
        response.headers["Content-Type"] = "text/html"
        mock_get.side_effect = [response, make_response(html="ok")]
        result = crawl("http://example.com/", max_pages=2)
        self.assertIn("http://example.com/%E6%97%A5%E6%9C%AC%E8%AA%9E", result)

    @patch("scanner.crawler.requests.get")
    def test_external_redirect_is_not_followed(self, mock_get):
        """外部ホストへのリダイレクトを自動追跡しない。"""
        mock_get.return_value = make_response(
            302,
            location="http://evil.example/",
        )

        result = crawl("http://example.com/", max_pages=10)

        self.assertEqual(result, set())
        mock_get.assert_called_once_with(
            "http://example.com/",
            timeout=5,
            allow_redirects=False,
        )

    @patch("scanner.crawler.requests.get")
    def test_external_link_is_not_crawled(self, mock_get):
        """ページ内の外部リンクを巡回しない。"""
        mock_get.side_effect = [
            make_response(
                html=(
                    '<a href="/inside">内部</a>'
                    '<a href="http://evil.example/">外部</a>'
                )
            ),
            make_response(html="<p>内部ページ</p>"),
        ]

        result = crawl("http://example.com/", max_pages=10)

        self.assertEqual(
            result,
            {
                "http://example.com/",
                "http://example.com/inside",
            },
        )
        self.assertEqual(mock_get.call_count, 2)

    @patch("scanner.crawler.requests.get")
    def test_same_host_port_is_required(self, mock_get):
        """別ポートへのリンクを巡回しない。"""
        mock_get.return_value = make_response(
            html='<a href="http://example.com:8000/">別ポート</a>'
        )

        result = crawl("http://example.com/", max_pages=10)

        self.assertEqual(result, {"http://example.com/"})
        mock_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
