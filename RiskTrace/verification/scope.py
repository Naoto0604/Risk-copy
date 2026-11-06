"""診断スコープの定義と判定。

スコープは「証明済みの対象」から組み立てる。ここは判定だけを持ち、
名前解決は呼び出し側から注入する（ソケットを直接叩かない）。

判定の原則:
    - ホストは完全一致。サブドメインを自動的に許可しない
    - ポート・パスも明示された範囲のみ
    - 解決結果に拒否対象が1つでも含まれれば拒否
    - ループバック・プライベート・リンクローカル・予約済みは既定で拒否
    - プライベート許可は全体許可（allow_private）と CIDR 個別許可の2段

リダイレクト先の判定にも同じ ``allows`` を使う。
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}

_HOST_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

#: 拒否対象の分類。
PRIVATE_CLASSES = frozenset({"loopback", "private", "link_local", "reserved", "unspecified"})

Resolver = Callable[[str], Iterable[str]]


class ScopeError(ValueError):
    """スコープ定義が不正。"""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


ALLOW = Decision(True)


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


def normalize_host(host: str) -> str:
    """ホスト名を比較用に正規化する。末尾ドットは落とす。"""
    return (host or "").strip().lower().rstrip(".")


def classify_ip(value: str) -> str:
    """IP の分類を返す。global 以外は既定で拒否対象。"""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return "invalid"

    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_unspecified:
        return "unspecified"
    if address.is_multicast:
        return "multicast"
    if address.is_private:
        return "private"
    if address.is_reserved:
        return "reserved"
    return "global"


def _port_of(parts) -> int | None:
    if parts.port is not None:
        return parts.port
    return DEFAULT_PORTS.get(parts.scheme.lower())


@dataclass(frozen=True)
class Scope:
    """許可された診断範囲。"""

    hosts: frozenset[str]
    ports: frozenset[int]
    path_prefixes: tuple[str, ...] = ("/",)
    allow_private: bool = False
    private_cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        hosts = frozenset(normalize_host(h) for h in self.hosts if normalize_host(h))
        if not hosts:
            raise ScopeError("hosts は1件以上必要です")
        for host in hosts:
            if not _HOST_PATTERN.match(host):
                raise ScopeError(f"ホスト名として不正です: {host!r}")
        object.__setattr__(self, "hosts", hosts)

        if not self.ports:
            raise ScopeError("ports は1件以上必要です")
        for port in self.ports:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ScopeError(f"ポート番号が不正です: {port!r}")
        object.__setattr__(self, "ports", frozenset(self.ports))

        prefixes = tuple(self.path_prefixes) or ("/",)
        for prefix in prefixes:
            if not prefix.startswith("/"):
                raise ScopeError(f"パス前置詞は / で始まる必要があります: {prefix!r}")
        object.__setattr__(self, "path_prefixes", prefixes)

        networks = []
        for cidr in self.private_cidrs:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                raise ScopeError(f"CIDR が不正です: {cidr!r}") from exc
        object.__setattr__(self, "private_cidrs", tuple(networks))

    # --- 判定 -----------------------------------------------------------

    def allows_host(self, host: str) -> Decision:
        normalized = normalize_host(host)
        if not normalized:
            return _deny("ホスト名がありません")
        if normalized not in self.hosts:
            return _deny(f"スコープ外のホストです: {normalized}")
        return ALLOW

    def allows_port(self, port: int | None) -> Decision:
        if port is None:
            return _deny("ポートを特定できません")
        if port not in self.ports:
            return _deny(f"スコープ外のポートです: {port}")
        return ALLOW

    def allows_path(self, path: str) -> Decision:
        target = path or "/"
        for prefix in self.path_prefixes:
            if prefix == "/":
                return ALLOW
            boundary = prefix if prefix.endswith("/") else prefix + "/"
            if target == prefix.rstrip("/") or target.startswith(boundary):
                return ALLOW
        return _deny(f"スコープ外のパスです: {target}")

    def allows_address(self, value: str) -> Decision:
        kind = classify_ip(value)
        if kind == "global":
            return ALLOW
        if kind == "invalid":
            return _deny(f"IP として不正です: {value!r}")
        if self.allow_private:
            return ALLOW

        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return _deny(f"IP として不正です: {value!r}")
        for network in self.private_cidrs:
            if address in network:
                return ALLOW
        return _deny(f"拒否対象のアドレスです（{kind}）: {value}")

    def allows(self, url: str) -> Decision:
        """URL が許可範囲か判定する。"""
        try:
            parts = urlsplit(url)
        except (TypeError, ValueError):
            return _deny(f"URL を解析できません: {url!r}")

        if parts.scheme.lower() not in DEFAULT_PORTS:
            return _deny(f"http/https 以外のスキームです: {parts.scheme}")

        decision = self.allows_host(parts.hostname or "")
        if not decision:
            return decision

        decision = self.allows_port(_port_of(parts))
        if not decision:
            return decision

        return self.allows_path(parts.path)

    def allows_resolved(self, host: str, addresses: Iterable[str]) -> Decision:
        """解決結果を含めた判定。拒否対象が1つでも混ざれば拒否する。"""
        decision = self.allows_host(host)
        if not decision:
            return decision

        values = [value for value in addresses if value]
        if not values:
            return _deny(f"名前解決できません: {host}")

        for value in values:
            decision = self.allows_address(value)
            if not decision:
                return decision
        return ALLOW

    def check(self, url: str) -> None:
        """許可されていなければ ScopeError を投げる。"""
        decision = self.allows(url)
        if not decision:
            raise ScopeError(decision.reason)

    # --- 補助 -----------------------------------------------------------

    def describe(self) -> dict:
        """レポート・ログ用の説明。"""
        return {
            "hosts": sorted(self.hosts),
            "ports": sorted(self.ports),
            "path_prefixes": list(self.path_prefixes),
            "allow_private": self.allow_private,
            "private_cidrs": [str(network) for network in self.private_cidrs],
        }


def default_resolver(host: str) -> list[str]:
    """``getaddrinfo`` による解決。重複は落とす。"""
    infos = socket.getaddrinfo(host, None)
    addresses = []
    for info in infos:
        value = info[4][0]
        if value not in addresses:
            addresses.append(value)
    return addresses


def build_checker(scope: Scope, resolver: Resolver | None = None) -> Callable[[str], bool]:
    """Scheduler に渡す判定関数を作る。

    名前解決も行うため、通信前の最終ゲートとして使う。
    """
    resolve = resolver or default_resolver

    def checker(url: str) -> bool:
        decision = scope.allows(url)
        if not decision:
            return False
        host = urlsplit(url).hostname or ""
        try:
            addresses = list(resolve(host))
        except OSError:
            return False
        return bool(scope.allows_resolved(host, addresses))

    return checker