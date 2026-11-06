"""旧 app.py 向けのクロールブリッジ。

v1 の `scanner/crawler.py` を置き換える。実装は v2 の Collector に寄せ、
ここでは `set[str]` を返すだけにする。

v1 の crawl は「辿れた URL の集合」を返すだけだった。判定はしない。
"""

from __future__ import annotations

from collectors.explore import crawl
from engine.scheduler import Budgets, Scheduler


def _scheduler() -> Scheduler:
    instance = Scheduler(Budgets(per_host_interval=0.001), scope=lambda url: True)
    instance.start()
    return instance


def normalize_url(url: str) -> str | None:
    """v1 と同じ名前で v2 の正規化を出す。"""
    return crawl.normalize_url(url)


def crawl_urls(start_url: str, max_pages: int = 100, *, transport=None) -> set[str]:
    """同一オリジン内を辿り、到達できた URL の集合を返す。"""
    normalized = crawl.normalize_url(start_url)
    if normalized is None:
        raise ValueError("開始URLが不正です")

    limit = max(1, min(int(max_pages), crawl.MAX_PAGES_HARD))
    observation = crawl.collect(normalized, _scheduler(), max_pages=limit,
                                transport=transport)

    return {
        page["url"]
        for page in observation.data.get("pages", [])
        if page.get("status") is not None
    }