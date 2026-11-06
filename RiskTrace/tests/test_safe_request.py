import unittest
from unittest.mock import patch, MagicMock
import requests
from app import safe_request, MAX_REDIRECTS

def make_response(status_code, location=None):
    """テスト用のHTTPレスポンスを作る。"""
    response = requests.Response()
    response.status_code = status_code
    response._content = b"Test response"
    response.headers = {}
    response.raw = MagicMock()

    if location is not None:
        response.headers["Location"] = location

    return response

class TestSafeRequest(unittest.TestCase):

    @patch("app.requests.get")
    def test_normal_response(self, mock_get):
        """通常のページはそのまま返す。"""
        expected = make_response(200)
        mock_get.return_value = expected

        result = safe_request("https://example.com/")

        self.assertIs(result, expected)
        mock_get.assert_called_once()

    @patch("app.requests.get")
    def test_same_host_redirect(self, mock_get):
        """同じホストへのリダイレクトは追跡する。"""
        redirect = make_response(302, "/next")
        final_response = make_response(200)
        mock_get.side_effect = [redirect, final_response]

        result = safe_request("https://example.com/start")

        self.assertIs(result, final_response)
        self.assertEqual(len(result.history), 1)
        self.assertEqual(mock_get.call_count, 2)

    @patch("app.requests.get")
    def test_external_host_is_rejected(self, mock_get):
        """外部ホストへのリダイレクトは拒否する。"""
        mock_get.return_value = make_response(
            302, "https://other.example/"
        )

        with self.assertRaises(requests.RequestException):
            safe_request("https://example.com/")

        # 外部ホストにはリクエストしていない
        mock_get.assert_called_once()

    @patch("app.requests.get")
    def test_redirect_limit(self, mock_get):
        """リダイレクト回数の上限で停止する。"""
        mock_get.side_effect = [
            make_response(302, "/loop")
            for _ in range(MAX_REDIRECTS + 1)
        ]

        with self.assertRaises(requests.TooManyRedirects):
            safe_request("https://example.com/loop")

        self.assertEqual(
            mock_get.call_count,
            MAX_REDIRECTS + 1,
        )


if __name__ == "__main__":
    unittest.main()
