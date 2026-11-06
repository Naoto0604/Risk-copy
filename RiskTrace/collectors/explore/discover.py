"""Sitemap と既知パスからの URL 発見。

観測のみ。severity も confidence も決めない。
「そこに何かあるか」だけを残し、中身の評価はルール側で行う。

方針:
    - Sitemap は robots.txt の ``Sitemap:`` 行と ``/sitemap.xml`` から辿る
    - sitemapindex は 1 段だけ展開する（無限に潜らない）
    - 既知パスは 200/401/403/404 の区別だけを残す。判定はしない
    - 正規化・オリジン判定・robots 尊重は crawl の関数をそのまま使う
    - 打ち切り理由は必ず残す。中断（Cancelled）だけは伝播させる

取得は GET。HEAD はサーバーによって 405 を返し、存在確認の意味が濁るため。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from collectors.explore import crawl
from collectors.http import client
from engine.observations import Observation
from engine.scheduler import BudgetExhausted, ScopeViolation, TimeBudgetExhausted

COLLECTOR = "explore_discover"

SITEMAP_PATH = "/sitemap.xml"

MAX_SITEMAPS = 3
MAX_URLS = 300
MAX_PROBES = 40

#: 発見したい既知パス。robots.txt と sitemap.xml は別途取得するので含めない。
KNOWN_PATHS: tuple[str, ...] = (
    "/.git/HEAD",
    "/.env",
    "/.well-known/security.txt",
    "/admin",
    "/admin/",
    "/api",
    "/backup.zip",
    "/config.json",
    "/login",
    "/phpinfo.php",
    "/server-status",
    "/wp-admin/",
    "/wp-login.php",
)

#: prefix を残す Content-Type。
TEXT_TYPES = ("text/html", "text/plain", "application/json", "application/xml")

PREFIX_LENGTH = 100


def _outcome(status: int | None) -> str:
    """状態コードを「存在の意味」に落とす。判定ではない。"""
    if status is None:
        return "error"
    if 200 <= status < 300:
        return "found"
    if status in (401, 403):
        return "gated"
    if status in (404, 410):
        return "absent"
    return "other"


def _prefix(response) -> str | None:
    """本文の先頭だけ残す。テキスト系以外は None。"""
    if not response.content_type.lower().startswith(TEXT_TYPES):
        return None
    text = response.body.strip()
    return text[:PREFIX_LENGTH] or None


def _sitemap_locs(body: str) -> tuple[list[str], list[str]]:
    """sitemap を (URL 一覧, 子 sitemap 一覧) に分ける。"""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return [], []

    root_tag = root.tag.rsplit("}", 1)[-1]
    if root_tag not in ("urlset", "sitemapindex"):
        return [], []

    values: list[str] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "loc":
            continue
        text = (element.text or "").strip()
        if text:
            values.append(text)

    return ([], values) if root_tag == "sitemapindex" else (values, [])


def _fetch_robots(start: str, scheduler, transport):
    """robots 規則と ``Sitemap:`` 行を取る。失敗しても発見は続ける。"""
    try:
        response = client.fetch(crawl._robots_url(start), scheduler, transport=transport)
    except (client.FetchError, ScopeViolation):
        return crawl._Robots(), ()
    except (BudgetExhausted, TimeBudgetExhausted):
        return crawl._Robots(), ()

    if response.status != 200:
        return crawl._Robots(), ()

    sitemaps: list[str] = []
    for line in response.body.splitlines():
        field, _, value = line.partition(":")
        if field.strip().lower() == "sitemap" and value.strip():
            sitemaps.append(value.strip())

    return crawl._Robots(crawl.parse_robots(response.body), "fetched"), tuple(sitemaps)


def _accept(candidate: str, origin, robots, seen: set[str], skipped: list[dict]) -> bool:
    """巡回対象として採用してよいか。理由は必ず残す。"""
    if candidate in seen:
        return False

    reason = None
    if crawl.origin_of(candidate) != origin:
        reason = "out_of_scope"
    elif not robots.allows(urlsplit(candidate).path or "/"):
        reason = "robots"

    if reason is not None:
        if len(skipped) < crawl.MAX_SKIPS:
            skipped.append({"url": candidate, "reason": reason})
        return False

    seen.add(candidate)
    return True


def collect(
    start: str,
    scheduler,
    *,
    paths: tuple[str, ...] = KNOWN_PATHS,
    include_sitemap: bool = True,
    transport: client.Transport | None = None,
) -> Observation:
    """Sitemap と既知パスから URL を集める。"""
    start_url = crawl.normalize_url(start)
    if start_url is None:
        return Observation.error(COLLECTOR, start, "URL を正規化できません")

    origin = crawl.origin_of(start_url)
    if origin is None:
        return Observation.error(COLLECTOR, start, "オリジンを判定できません")

    robots, robot_sitemaps = _fetch_robots(start_url, scheduler, transport)

    seen: set[str] = {start_url}
    skipped: list[dict] = []
    truncated: str | None = None

    sitemaps: list[dict] = []
    urls: list[str] = []

    queue: list[str] = []
    if include_sitemap:
        queue.append(f"{origin[0]}://{urlsplit(start_url).netloc}{SITEMAP_PATH}")
        queue.extend(robot_sitemaps)

    while queue:
        if len(sitemaps) >= MAX_SITEMAPS:
            truncated = truncated or "sitemaps"
            break

        target = queue.pop(0)
        normalized = crawl.normalize_url(target)
        if normalized is None:
            continue

        record: dict = {"url": normalized, "status": None, "urls": 0, "error": None}
        sitemaps.append(record)

        if crawl.origin_of(normalized) != origin or not robots.allows(
            urlsplit(normalized).path or "/"
        ):
            record["error"] = "out_of_scope"
            continue

        try:
            response = client.fetch(normalized, scheduler, transport=transport)
        except client.FetchError as exc:
            record["error"] = str(exc)
            continue
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
            break

        record["status"] = response.status
        if response.status != 200:
            continue

        locs, nested = _sitemap_locs(response.body)
        queue.extend(nested)

        for loc in locs:
            if len(urls) >= MAX_URLS:
                truncated = "urls"
                break
            candidate = crawl.normalize_url(loc)
            if candidate is not None and _accept(candidate, origin, robots, seen, skipped):
                urls.append(candidate)
        record["urls"] = len(locs)

    probes: list[dict] = []
    for path in tuple(paths)[:MAX_PROBES]:
        if truncated == "budget":
            break

        candidate = crawl.normalize_url(f"{origin[0]}://{urlsplit(start_url).netloc}{path}")
        if candidate is None:
            continue
        if candidate in seen:
            continue
        if not robots.allows(urlsplit(candidate).path or "/"):
            if len(skipped) < crawl.MAX_SKIPS:
                skipped.append({"url": candidate, "reason": "robots"})
            continue
        seen.add(candidate)

        try:
            response = client.fetch(candidate, scheduler, transport=transport)
        except client.FetchError as exc:
            probes.append({"path": path, "url": candidate, "status": None,
                           "outcome": "error", "content_type": None, "prefix": None,
                           "error": str(exc)})
            continue
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
            break

        probes.append({
            "path": path,
            "url": candidate,
            "status": response.status,
            "outcome": _outcome(response.status),
            "content_type": response.content_type,
            "prefix": _prefix(response),
            "error": None,
        })

    found_paths = [probe["path"] for probe in probes if probe["outcome"] == "found"]
    gated_paths = [probe["path"] for probe in probes if probe["outcome"] == "gated"]

    note = None
    if truncated == "budget":
        note = "予算または時間の上限に達したため打ち切り"
    elif truncated == "sitemaps":
        note = f"Sitemap 上限 {MAX_SITEMAPS} に達したため打ち切り"
    elif truncated == "urls":
        note = f"URL 上限 {MAX_URLS} に達したため打ち切り"

    return Observation.ok(
        COLLECTOR,
        start_url,
        {
            "start": start_url,
            "host": origin[1],
            "sitemaps": sitemaps,
            "urls": urls,
            "probes": probes,
            "found": [probe["url"] for probe in probes if probe["outcome"] in ("found", "gated")],
            "found_paths": found_paths,
            "gated_paths": gated_paths,
            "skipped": skipped,
            "robots": robots.state,
            "truncated": truncated is not None,
            "truncated_reason": truncated,
        },
        note=note,
    )