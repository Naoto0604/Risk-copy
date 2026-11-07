"""v1 の安全な取得。リダイレクトを手動で追い、範囲外を拒否する。

v2 の ``collectors.http.client`` とは別実装。v1 の画面が使う。
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 5
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def safe_request(url):
    """リダイレクトを制御しながら HTTP リクエストを実行する。"""
    original_parsed = urlparse(url)

    if (
        original_parsed.scheme not in ("http", "https")
        or not original_parsed.hostname
        or original_parsed.username is not None
        or original_parsed.password is not None
    ):
        raise requests.RequestException(f"開始URLが不正です: {url}")

    original_host = original_parsed.netloc.lower()

    redirect_history = []
    current_url = url

    for redirect_count in range(MAX_REDIRECTS + 1):

        response = requests.get(current_url, timeout=5, allow_redirects=False)

        if response.status_code not in REDIRECT_STATUSES:
            response.history = redirect_history
            return response

        location = response.headers.get("Location")

        if not location:
            response.history = redirect_history
            return response

        if redirect_count >= MAX_REDIRECTS:
            response.close()
            raise requests.TooManyRedirects(
                f"リダイレクト回数が上限({MAX_REDIRECTS})を超えました: {url}"
            )

        next_url = urljoin(current_url, location)
        parsed_next = urlparse(next_url)

        if parsed_next.scheme not in ("http", "https"):
            response.close()
            raise requests.RequestException(f"Redirect先のプロトコルが不正です: {next_url}")

        if (
            not parsed_next.hostname
            or parsed_next.username is not None
            or parsed_next.password is not None
        ):
            response.close()
            raise requests.RequestException(f"Redirect先のURLが不正です: {next_url}")

        if parsed_next.netloc.lower() != original_host:
            response.close()
            raise requests.RequestException(
                f"診断対象外へのRedirectを拒否しました: {next_url}"
            )

        if urlparse(current_url).scheme == "https" and parsed_next.scheme == "http":
            response.close()
            raise requests.RequestException(
                f"HTTPSからHTTPへのRedirectを拒否しました: {next_url}"
            )

        redirect_history.append(response)
        current_url = next_url

    raise requests.TooManyRedirects(f"リダイレクト回数が上限を超えました: {url}")