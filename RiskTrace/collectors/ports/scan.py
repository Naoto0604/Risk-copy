"""固定リストのポート到達性を観測する Collector。

観測のみ。severity も confidence も決めない。
接続できたか、閉じているか、黙っているか、バナーが何かだけを残す。

方針:
    - 全ポート走査ではなく固定リスト。網羅性は主張しない
    - 接続判定は connect_ex。拒否と無応答を区別する
    - バナーは一部のポートだけ読む。読めなくても失敗にしない
    - スコープ検証は URL 形式に組み立てて既存のスコープ判定に委ねる
    - 予算は 1 ポート 1 リクエストとして消費する
    - 中断（Cancelled）は伝播させる。予算・時間切れは打ち切り扱い
"""

from __future__ import annotations

import socket
import ipaddress
from typing import Callable
from urllib.parse import urlsplit

from engine.observations import Observation
from engine.scheduler import BudgetExhausted, ScopeViolation, TimeBudgetExhausted

COLLECTOR = "ports"

#: 試すポート。固定リストであり、全 TCP の走査ではない。
TARGET_PORTS: tuple[int, ...] = (
    21, 22, 25, 80, 443, 587, 1433, 3000, 3306, 3389,
    5000, 5432, 6379, 8000, 8080, 8443, 27017,
)

#: バナーを読むポート。挨拶を返すプロトコルに限る。
BANNER_PORTS = frozenset({21, 22, 25, 587, 1433, 3306, 5432, 6379, 27017})

#: そのポートが慣例的に何に使われるか。断定ではない。
CONVENTIONAL = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    443: "https",
    587: "smtp-submission",
    1433: "mssql",
    3000: "dev-web",
    3306: "mysql",
    3389: "rdp",
    5000: "dev-web",
    5432: "postgresql",
    6379: "redis",
    8000: "dev-web",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}

TLS_PORTS = frozenset({443, 8443})

MAX_PORTS = 30
PORT_TIMEOUT = 2.0
BANNER_TIMEOUT = 1.0
BANNER_LIMIT = 120

#: プライベート範囲。文書用・特殊用途の IP を巻き込まないよう明示する。
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

#: 接続拒否として扱う errno。POSIX と Windows の両方を入れる。
REFUSED = frozenset({111, 10061})
TIMED_OUT = frozenset({110, 10060})

Probe = Callable[[str, int, float], tuple[str, str | None, str | None]]

def _state_of(code: int) -> str:
    if code in REFUSED:
        return "closed"
    if code in TIMED_OUT:
        return "filtered"
    return "error"


def _clean(raw: bytes) -> str | None:
    """バナーを 1 行に潰す。制御文字は落とす。"""
    text = raw.decode("latin-1", errors="replace")
    text = "".join(char if 32 <= ord(char) < 127 else " " for char in text)
    text = " ".join(text.split())
    return text[:BANNER_LIMIT] or None


def _probe(host: str, port: int, timeout: float) -> tuple[str, str | None, str | None]:
    """1 ポートを試す。バナーは必要なポートだけ読む。

    接続できた場合は実際の接続先 IP を返す。範囲の判定は呼び出し側で行う。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((host, port))
        if code != 0:
            return _state_of(code), None, None

        try:
            peer = sock.getpeername()[0]
        except OSError:
            peer = None

        if port not in BANNER_PORTS:
            return "open", None, peer

        sock.settimeout(min(timeout, BANNER_TIMEOUT))
        try:
            return "open", _clean(sock.recv(256)), peer
        except (socket.timeout, OSError):
            return "open", None, peer
    finally:
        sock.close()


def classify_peer(address: str | None) -> str:
    """接続先 IP の範囲を返す。DNS 名は解決しない。"""
    text = (address or "").strip()
    if not text:
        return "UNKNOWN"

    lower = text.lower().rstrip(".")
    if lower == "localhost" or lower.endswith(".localhost"):
        return "LOOPBACK"

    try:
        parsed = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return "UNKNOWN"

    if getattr(parsed, "ipv4_mapped", None) is not None:
        parsed = parsed.ipv4_mapped

    if parsed.is_loopback:
        return "LOOPBACK"
    if parsed.is_link_local:
        return "LINK_LOCAL"
    if any(parsed.version == net.version and parsed in net for net in PRIVATE_NETWORKS):
        return "PRIVATE"
    if parsed.is_multicast:
        return "MULTICAST"
    if parsed.is_unspecified:
        return "UNSPECIFIED"
    if parsed.is_global:
        return "PUBLIC"
    return "UNKNOWN"


def _unpack(probed) -> tuple[str, str | None, str | None]:
    """probe の戻り値を3要素に揃える。2要素の probe も受ける。"""
    if len(probed) == 3:
        return probed
    state, banner = probed
    return state, banner, None


def _host_of(target: str) -> str | None:
    text = (target or "").strip()
    if "://" in text:
        try:
            return urlsplit(text).hostname or None
        except ValueError:
            return None
    return text.split("/", 1)[0] or None


def _scope_target(host: str, port: int) -> str:
    scheme = "https" if port in TLS_PORTS else "http"
    return f"{scheme}://{host}:{port}/"


def collect(
    target: str,
    scheduler,
    *,
    ports: tuple[int, ...] = TARGET_PORTS,
    connect: Probe | None = None,
) -> Observation:
    """固定リストのポートを試し、状態を返す。"""
    host = _host_of(target)
    if not host:
        return Observation.error(COLLECTOR, target or "-", "ホスト名を取得できません")

    probe = connect or _probe
    candidates = [port for port in tuple(ports)[:MAX_PORTS] if 1 <= port <= 65535]
    if not candidates:
        return Observation.error(COLLECTOR, host, "試すポートがありません")

    results: list[dict] = []
    truncated: str | None = None

    for port in candidates:
        scheduler.check_cancel()
        scheduler.check_time()

        try:
            scheduler.check_scope(_scope_target(host, port))
        except ScopeViolation:
            results.append({"port": port, "state": "out_of_scope", "banner": None,
                            "peer": None, "scope": None, "error": None,
                            "conventional": CONVENTIONAL.get(port)})
            continue

        try:
            scheduler.reserve("request")
            timeout = min(scheduler.http_timeout()[1], PORT_TIMEOUT)
            with scheduler.slot(host):
                state, banner, peer = _unpack(probe(host, port, timeout))
        except (BudgetExhausted, TimeBudgetExhausted):
            truncated = "budget"
            break
        except OSError as exc:
            results.append({"port": port, "state": "error", "banner": None,
                            "peer": None, "scope": None,
                            "error": f"{type(exc).__name__}: {exc}",
                            "conventional": CONVENTIONAL.get(port)})
            continue

        results.append({"port": port, "state": state, "banner": banner,
                        "peer": peer,
                        "scope": classify_peer(peer) if state == "open" else None,
                        "error": None,
                        "conventional": CONVENTIONAL.get(port)})
        
    open_entries = [entry for entry in results if entry["state"] == "open"]
    open_ports = [entry["port"] for entry in open_entries]

    counts = {
        state: sum(1 for entry in results if entry["state"] == state)
        for state in ("open", "closed", "filtered", "error", "out_of_scope")
    }
    scope_counts: dict[str, int] = {}
    for entry in open_entries:
        key = entry["scope"] or "UNKNOWN"
        scope_counts[key] = scope_counts.get(key, 0) + 1

    note = "予算または時間の上限に達したため打ち切り" if truncated else None

    return Observation.ok(
        COLLECTOR,
        host,
        {
            "host": host,
            "ports": results,
            "open": open_ports,
            "open_external": [e["port"] for e in open_entries if e["scope"] != "LOOPBACK"],
            "open_loopback": [e["port"] for e in open_entries if e["scope"] == "LOOPBACK"],
            "scope_counts": scope_counts,
            "counts": counts,
            "tried": len(results),
            "truncated": truncated is not None,
            "truncated_reason": truncated,
        },
        note=note,
    )