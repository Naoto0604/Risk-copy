"""ページ内のアセット参照を集める Collector。

観測のみ。severity も confidence も決めない。
どのページが、どのタグで、どこを参照しているかだけを残す。

方針:
    - 参照を解決するだけで、アセット自体は取得しない
    - 同一オリジンか外部オリジンかだけを分類する
    - ``integrity`` と ``crossorigin`` の有無を残す（SRI の判断はルール側）
    - data: / blob: / javascript: などは件数だけ残す
    - 正規化・オリジン判定・robots は crawl の関数をそのまま使う
    - 中断（Cancelled）は伝播させる。予算・時間切れは打ち切り扱い
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from collectors.explore import crawl
from collectors.http import client
from engine.observations import Observation
from engine.scheduler import BudgetExhausted, ScopeViolation, TimeBudgetExhausted

COLLECTOR = "explore_assets"

MAX_PAGES_DEFAULT = 10
MAX_PAGES_HARD = 25
MAX_ASSETS_PER_PAGE = 200
MAX_ASSETS_TOTAL = 500

HTML_TYPES = ("text/html", "application/xhtml+xml")

#: 参照を持つタグと属性。
ASSET_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "script": ("src",),
    "link": ("href",),
    "img": ("src", "srcset"),
    "iframe": ("src",),
    "form": ("action",),
    "source": ("src", "srcset"),
    "video": ("src",),
    "audio": ("src",),
    "object": ("data",),
}

#: SRI を持てるタグ。
SRI_TAGS = ("script", "link")


class _AssetParser(HTMLParser):
    """対象タグの属性だけを集める。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in ASSET_ATTRIBUTES:
            self.items.append((tag, dict(attrs)))


def _split_srcset(value: str) -> list[str]:
    """srcset を URL 単位に割る。記述子は落とす。"""
    candidates = []
    for part in value.split(","):
        text = part.strip()
        if not text:
            continue
        candidates.append(text.split(" ")[0])
    return candidates


def extract_assets(body: str, base: str) -> tuple[list[dict], int]:
    """本文から参照を集める。解決できない参照は件数だけ返す。"""
    parser = _AssetParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - 壊れた HTML で止めない
        pass

    assets: list[dict] = []
    unresolved = 0

    for tag, attrs in parser.items:
        for attribute in ASSET_ATTRIBUTES[tag]:
            raw = attrs.get(attribute)
            if not raw:
                continue

            values = _split_srcset(raw) if attribute == "srcset" else [raw]
            for value in values:
                try:
                    absolute = urljoin(base, value.strip())
                except ValueError:
                    unresolved += 1
                    continue

                normalized = crawl.normalize_url(absolute)
                if normalized is None:
                    unresolved += 1
                    continue

                assets.append({
                    "url": normalized,
                    "tag": tag,
                    "attribute": attribute,
                    "integrity": bool(attrs.get("integrity")) if tag in SRI_TAGS else None,
                    "crossorigin": "crossorigin" in attrs if tag in SRI_TAGS else None,
                })

    return assets, unresolved


def _classify(assets: list[dict], origin) -> list[dict]:
    """同一オリジンか外部かを付ける。判定ではなく分類。"""
    for asset in assets:
        asset["kind"] = "same" if crawl.origin_of(asset["url"]) == origin else "external"
        asset["host"] = urlsplit(asset["url"]).hostname
    return assets


def collect(
    urls,
    scheduler,
    *,
    max_pages: int = MAX_PAGES_DEFAULT,
    transport: client.Transport | None = None,
) -> Observation:
    """指定 URL のページを取得し、アセット参照を分類して返す。"""
    targets: list[str] = []
    seen: set[str] = set()
    for raw in urls or ():
        normalized = crawl.normalize_url(str(raw))
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        targets.append(normalized)

    if not targets:
        return Observation.error(COLLECTOR, "-", "有効な対象 URL がありません")

    origin = crawl.origin_of(targets[0])
    if origin is None:
        return Observation.error(COLLECTOR, targets[0], "オリジンを判定できません")

    page_limit = max(1, min(int(max_pages), MAX_PAGES_HARD))
    robots = crawl._load_robots(targets[0], scheduler, transport)

    pages: list[dict] = []
    skipped: list[dict] = []
    external_hosts: list[str] = []
    total = 0
    truncated: str | None = None

    for target in targets:
        if len(pages) >= page_limit:
            truncated = "pages"
            break
        if total >= MAX_ASSETS_TOTAL:
            truncated = "assets"
            break

        if not robots.allows(urlsplit(target).path or "/"):
            if len(skipped) < crawl.MAX_SKIPS:
                skipped.append({"url": target, "reason": "robots"})
            continue

        try:
            response = client.fetch(target, scheduler, transport=transport)
        except client.FetchError as exc:
            pages.append({"url": target, "status": None, "error": str(exc),
                          "assets": [], "counts": {}})
            continue
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
            break

        content_type = response.content_type.lower()
        if not content_type.startswith(HTML_TYPES):
            if len(skipped) < crawl.MAX_SKIPS:
                skipped.append({"url": target, "reason": "non_html"})
            continue

        found, unresolved = extract_assets(response.body, response.url)
        found = _classify(found, origin)[:MAX_ASSETS_PER_PAGE]
        total += len(found)

        for asset in found:
            host = asset["host"]
            if asset["kind"] == "external" and host and host not in external_hosts:
                external_hosts.append(host)

        pages.append({
            "url": response.url,
            "status": response.status,
            "error": None,
            "assets": found,
            "unresolved": unresolved,
            "counts": {
                "same": sum(1 for asset in found if asset["kind"] == "same"),
                "external": sum(1 for asset in found if asset["kind"] == "external"),
                "without_integrity": sum(
                    1 for asset in found if asset["integrity"] is False
                ),
            },
        })

    note = None
    if truncated == "pages":
        note = f"ページ上限 {page_limit} に達したため打ち切り"
    elif truncated == "assets":
        note = f"アセット上限 {MAX_ASSETS_TOTAL} に達したため打ち切り"
    elif truncated == "budget":
        note = "予算または時間の上限に達したため打ち切り"

    return Observation.ok(
        COLLECTOR,
        targets[0],
        {
            "targets": targets,
            "pages": pages,
            "external_hosts": external_hosts,
            "total_assets": total,
            "skipped": skipped,
            "robots": robots.state,
            "max_pages": page_limit,
            "truncated": truncated is not None,
            "truncated_reason": truncated,
        },
        note=note,
    )