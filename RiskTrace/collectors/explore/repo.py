"""`.git` 露出の観測。

観測のみ。severity も confidence も決めない。
「取れるか」「何が書いてあるか」だけを残す。GitHub への照会はしない。

方針:
    - 対象は `.git/HEAD`、`.git/config`、`.git/` の 3 つだけ
    - 状態は found / gated / absent / other に落とす。判定はしない
    - remote URL は資格情報を伏せて残す（``user:pass@`` を ``<masked>@``）
    - ブランチ名と detached かどうかは区別する
    - 正規化・オリジン判定・robots は crawl の関数をそのまま使う
    - 中断（Cancelled）は伝播させる。予算・時間切れは打ち切り扱い
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from collectors.explore import crawl
from collectors.http import client
from engine.observations import Observation
from engine.scheduler import BudgetExhausted, Cancelled, ScopeViolation, TimeBudgetExhausted

COLLECTOR = "explore_repo"

#: 見るパス。`.git/` はディレクトリ一覧の有無。
TARGET_PATHS: tuple[str, ...] = ("/.git/HEAD", "/.git/config", "/.git/")

TEXT_TYPES = ("text/plain", "text/html", "application/octet-stream", "application/x-git")

SNIPPET_LENGTH = 200

_REF = re.compile(r"^ref:\s*(\S+)\s*$", re.MULTILINE)
_HEX = re.compile(r"^[0-9a-f]{40}$")
_REMOTE_HEADER = re.compile(r'^\[remote\s+"([^"]+)"\]\s*$')
_URL_LINE = re.compile(r"^\s*url\s*=\s*(\S.*)$")

#: remote のホストから推定する区分。断定ではない。
PROVIDERS = (
    ("github.com", "github"),
    ("gitlab.com", "gitlab"),
    ("bitbucket.org", "bitbucket"),
    ("codeberg.org", "codeberg"),
)


def _outcome(status: int | None) -> str:
    if status is None:
        return "error"
    if 200 <= status < 300:
        return "found"
    if status in (401, 403):
        return "gated"
    if status in (404, 410):
        return "absent"
    return "other"


def _snippet(response) -> str | None:
    if not response.content_type.lower().startswith(TEXT_TYPES):
        return None
    text = response.body.strip()
    return text[:SNIPPET_LENGTH] or None


def _mask_credentials(url: str) -> str:
    """``user:pass@host`` の資格情報部分を伏せる。"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.username and not parts.password:
        return url
    netloc = f"<masked>@{parts.hostname or ''}"
    if parts.port is not None:
        netloc += f":{parts.port}"
    return parts._replace(netloc=netloc).geturl()


def parse_config(body: str) -> list[dict]:
    """config から remote 名と URL を取り出す。"""
    remotes: list[dict] = []
    current: str | None = None

    for line in body.splitlines():
        header = _REMOTE_HEADER.match(line)
        if header:
            current = header.group(1)
            continue

        if line.startswith("["):
            current = None
            continue

        if current is None:
            continue

        match = _URL_LINE.match(line)
        if not match:
            continue

        raw = match.group(1).strip()
        host = _remote_host(raw)
        remotes.append({
            "name": current,
            "url": _mask_credentials(raw),
            "host": host,
            "provider": _provider(host),
        })
        current = None

    return remotes


def _remote_host(url: str) -> str | None:
    """https でも scp 形式（git@host:path）でもホストを取り出す。"""
    if "://" in url:
        try:
            return (urlsplit(url).hostname or "").lower() or None
        except ValueError:
            return None
    if "@" in url and ":" in url:
        tail = url.split("@", 1)[1]
        return tail.split(":", 1)[0].lower() or None
    return None


def _provider(host: str | None) -> str | None:
    if not host:
        return None
    for suffix, name in PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return name
    return "other"


def collect(
    target: str,
    scheduler,
    *,
    transport: client.Transport | None = None,
) -> Observation:
    """`.git` 配下の露出を観測する。"""
    start = crawl.normalize_url(target)
    if start is None:
        return Observation.error(COLLECTOR, target or "-", "URL を正規化できません")

    origin = crawl.origin_of(start)
    if origin is None:
        return Observation.error(COLLECTOR, start, "オリジンを判定できません")

    base = f"{origin[0]}://{urlsplit(start).netloc}"
    robots = crawl._load_robots(start, scheduler, transport)

    paths: list[dict] = []
    skipped: list[dict] = []
    truncated: str | None = None

    head_branch: str | None = None
    head_detached: bool | None = None
    remotes: list[dict] = []

    for path in TARGET_PATHS:
        url = base + path
        if not robots.allows(path):
            skipped.append({"url": url, "reason": "robots"})
            continue

        try:
            response = client.fetch(url, scheduler, transport=transport)
        except client.FetchError as exc:
            paths.append({"path": path, "status": None, "outcome": "error",
                          "content_type": None, "snippet": None, "error": str(exc)})
            continue
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
            break

        record = {
            "path": path,
            "status": response.status,
            "outcome": _outcome(response.status),
            "content_type": response.content_type,
            "snippet": _snippet(response),
            "error": None,
        }
        paths.append(record)

        if record["outcome"] != "found":
            continue

        if path.endswith("HEAD"):
            ref = _REF.search(response.body)
            if ref:
                head_branch = ref.group(1)
                head_detached = False
            elif _HEX.match(response.body.strip()):
                head_detached = True
        elif path.endswith("config"):
            remotes = parse_config(response.body)

    head_exposed = any(
        entry["path"] == "/.git/HEAD" and entry["outcome"] == "found" for entry in paths
    )
    config_exposed = any(
        entry["path"] == "/.git/config" and entry["outcome"] == "found" for entry in paths
    )
    listing_exposed = any(
        entry["path"] == "/.git/" and entry["outcome"] == "found" for entry in paths
    )

    exposed = any(entry["outcome"] == "found" for entry in paths)
    note = "予算または時間の上限に達したため打ち切り" if truncated else None

    return Observation.ok(
        COLLECTOR,
        start,
        {
            "start": start,
            "host": origin[1],
            "paths": paths,
            "exposed": exposed,
            "head_exposed": head_exposed,
            "config_exposed": config_exposed,
            "listing_exposed": listing_exposed,
            "head_branch": head_branch,
            "head_detached": head_detached,
            "remotes": remotes,
            "providers": sorted({remote["provider"] for remote in remotes if remote["provider"]}),
            "skipped": skipped,
            "robots": robots.state,
            "truncated": truncated is not None,
            "truncated_reason": truncated,
        },
        note=note,
    )