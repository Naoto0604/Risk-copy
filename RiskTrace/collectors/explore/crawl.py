"""同一オリジン内の限定 BFS クローラー。

観測のみ。severity も confidence も決めない。
何ページ見たか、何を辿らなかったかだけを残す。

方針:
    - 同一オリジン（scheme・host・port が一致）だけを辿る
    - フラグメントは落とす。クエリは識別子として残す
    - robots.txt を尊重する。取得できなければ、または範囲外なら全許可
    - 深さとページ数に上限を置き、打ち切った理由を残す
    - 中断（Cancelled）は伝播させる。予算・時間切れは打ち切り扱い
    - ページ取得の失敗は握りつぶさず、そのページの error として残す

transport は差し替え可能。テストはネットワーク無しで回せる。
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlsplit

from collectors.http import client
from engine.observations import Observation
from engine.scheduler import BudgetExhausted, ScopeViolation, TimeBudgetExhausted

COLLECTOR = "explore_crawl"

ROBOTS_PATH = "/robots.txt"
USER_AGENT = "RiskTrace"

MAX_PAGES_DEFAULT = 20
MAX_PAGES_HARD = 50
MAX_DEPTH_DEFAULT = 2
MAX_DEPTH_HARD = 3

#: 記録するスキップ理由の上限。無制限に増やさない。
MAX_SKIPS = 200

HTML_TYPES = ("text/html", "application/xhtml+xml")

DEFAULT_PORTS = {"http": 80, "https": 443}

#: 辿る対象の属性。アセット（img/script/link）は次単位。
LINK_ATTRIBUTES = {
    "a": ("href",),
    "area": ("href",),
    "form": ("action",),
    "iframe": ("src",),
}

_SKIP_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#")


def normalize_url(url: str) -> str | None:
    """URL を比較用の形に正規化する。http/https 以外は None。

    パスとクエリはパーセントエンコードで揃える。非 ASCII と、
    すでにエスケープ済みの表記が同じ識別子になるようにするため。
    """
    try:
        parts = urlsplit((url or "").strip())
        port = parts.port
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        return None

    host = (parts.hostname or "").lower()
    if not host:
        return None
    if parts.username or parts.password:
        return None

    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"

    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~%")
    if not path.startswith("/"):
        path = "/" + path
    query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~%")
    query = f"?{query}" if query else ""

    path = re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), path)
    query = re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), query)

    return f"{scheme}://{netloc}{path}{query}"

def origin_of(url: str) -> tuple[str, str, int] | None:
    """同一オリジン判定用のキー。"""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    return (scheme, host, port if port is not None else DEFAULT_PORTS[scheme])


class _LinkParser(HTMLParser):
    """href / action / src だけを拾う。値の解釈はしない。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        wanted = LINK_ATTRIBUTES.get(tag)
        if not wanted:
            return
        for name, value in attrs:
            if value and name in wanted:
                self.links.append(value)


def extract_links(body: str, base: str) -> list[str]:
    """本文から絶対 URL を集める。解決できないものは捨てる。"""
    parser = _LinkParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - 壊れた HTML で巡回を止めない
        pass

    found: list[str] = []
    for raw in parser.links:
        text = raw.strip()
        if not text or text.startswith(_SKIP_PREFIXES):
            continue
        try:
            absolute = urljoin(base, text)
        except ValueError:
            continue
        normalized = normalize_url(absolute)
        if normalized is not None:
            found.append(normalized)
    return found


def _pattern_matches(pattern: str, path: str) -> bool:
    """robots のパターン一致。``*`` は任意、末尾 ``$`` は終端固定。"""
    if pattern == "":
        return False
    anchored = pattern.endswith("$")
    core = pattern[:-1] if anchored else pattern
    expression = "^" + "".join(".*" if char == "*" else re.escape(char) for char in core)
    if anchored:
        expression += "$"
    return re.match(expression, path) is not None


def parse_robots(text: str) -> tuple[tuple[str, bool], ...]:
    """自 UA に効く規則だけを取り出す。``*`` より ``RiskTrace`` を優先する。"""
    groups: dict[str, list[tuple[str, bool]]] = {}
    agents: list[str] = []
    in_agent_block = False

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()

        if field == "user-agent":
            if not in_agent_block:
                agents = []
            agents.append(value.lower())
            in_agent_block = True
            continue

        if field in ("allow", "disallow"):
            in_agent_block = False
            for agent in agents:
                groups.setdefault(agent, []).append((value, field == "allow"))

    for key in (USER_AGENT.lower(), "*"):
        if key in groups:
            return tuple(groups[key])
    return ()


@dataclass(frozen=True)
class _Robots:
    rules: tuple[tuple[str, bool], ...] = ()
    state: str = "unavailable"

    def allows(self, path: str) -> bool:
        """最長一致で決める。同長なら Allow 優先。規則が無ければ許可。"""
        best_length = -1
        best_allowed = True
        for pattern, allowed in self.rules:
            if not _pattern_matches(pattern, path):
                continue
            if len(pattern) > best_length or (len(pattern) == best_length and allowed):
                best_length = len(pattern)
                best_allowed = allowed
        return best_allowed


def _robots_url(start: str) -> str:
    parts = urlsplit(start)
    return f"{parts.scheme}://{parts.netloc}{ROBOTS_PATH}"


def _load_robots(start: str, scheduler, transport) -> _Robots:
    """robots.txt を取得する。

    robots は補助情報なので、取得失敗・スコープ外・予算切れのいずれでも
    巡回自体は止めない。全許可として扱い、状態だけ残す。
    """
    try:
        response = client.fetch(_robots_url(start), scheduler, transport=transport)
    except (client.FetchError, ScopeViolation):
        return _Robots()
    except (BudgetExhausted, TimeBudgetExhausted):
        return _Robots()

    if response.status != 200:
        return _Robots()
    return _Robots(parse_robots(response.body), "fetched")


def _scope_allows(scheduler, url: str) -> bool:
    try:
        scheduler.check_scope(url)
    except ScopeViolation:
        return False
    return True


def collect(
    start: str,
    scheduler,
    *,
    max_depth: int = MAX_DEPTH_DEFAULT,
    max_pages: int = MAX_PAGES_DEFAULT,
    transport: client.Transport | None = None,
) -> Observation:
    """開始 URL から同一オリジン内を辿り、到達できた URL を返す。"""
    start_url = normalize_url(start)
    if start_url is None:
        return Observation.error(COLLECTOR, start, "URL を正規化できません")

    origin = origin_of(start_url)
    if origin is None:
        return Observation.error(COLLECTOR, start, "オリジンを判定できません")

    depth_limit = max(0, min(int(max_depth), MAX_DEPTH_HARD))
    page_limit = max(1, min(int(max_pages), MAX_PAGES_HARD))

    robots = _load_robots(start_url, scheduler, transport)

    pages: list[dict] = []
    skipped: list[dict] = []
    seen = {start_url}
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    truncated: str | None = None

    while queue:
        if len(pages) >= page_limit:
            truncated = "pages"
            break

        url, depth = queue.popleft()

        try:
            response = client.fetch(url, scheduler, transport=transport)
        except client.FetchError as exc:
            pages.append({"url": url, "depth": depth, "status": None, "error": str(exc)})
            continue
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
            break

        final = normalize_url(response.url) or url
        seen.add(final)

        content_type = response.content_type.lower()
        is_html = content_type.startswith(HTML_TYPES)
        record = {
            "url": final,
            "depth": depth,
            "status": response.status,
            "content_type": response.content_type,
            "redirected_from": response.redirects[-1] if response.redirects else None,
            "downgraded": response.downgraded,
            "links": 0,
        }
        pages.append(record)

        if not is_html:
            if len(skipped) < MAX_SKIPS:
                skipped.append({"url": final, "reason": "non_html"})
            continue
        if depth >= depth_limit:
            continue

        followed = 0
        for candidate in extract_links(response.body, final):
            if candidate in seen:
                continue

            reason = None
            if origin_of(candidate) != origin:
                reason = "out_of_scope"
            elif not _scope_allows(scheduler, candidate):
                reason = "out_of_scope"
            elif not robots.allows(urlsplit(candidate).path or "/"):
                reason = "robots"

            if reason is not None:
                if len(skipped) < MAX_SKIPS:
                    skipped.append({"url": candidate, "reason": reason})
                continue

            seen.add(candidate)
            queue.append((candidate, depth + 1))
            followed += 1

        record["links"] = followed

    note = None
    if truncated == "pages":
        note = f"ページ上限 {page_limit} に達したため打ち切り"
    elif truncated == "budget":
        note = "予算または時間の上限に達したため打ち切り"

    return Observation.ok(
        COLLECTOR,
        start_url,
        {
            "start": start_url,
            "host": origin[1],
            "urls": [page["url"] for page in pages],
            "pages": pages,
            "page_count": len(pages),
            "skipped": skipped,
            "robots": robots.state,
            "max_depth": depth_limit,
            "max_pages": page_limit,
            "truncated": truncated is not None,
            "truncated_reason": truncated,
        },
        note=note,
    )