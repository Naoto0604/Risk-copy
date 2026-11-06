"""旧 app.py 向けのポート検査ブリッジ。

v1 の `scanner/port_check.py` を置き換える。実装は v2 の Collector に寄せ、
ここでは Finding 辞書への変換だけを行う。

方針:
    - 判定は v1 の severity 規則をそのまま再現する（移行期間だけ）
    - ループバック経由は INFO。要確認ポートは LOW
    - Evidence は `Port:` と `Network scope:` の行を含める。旧 scoring が読む
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from collectors.ports import scan
from collectors.tls import probe as tls
from engine.scheduler import Budgets, Scheduler

#: 要確認として LOW で報告するポート。
SENSITIVE_PORTS = frozenset(
    {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 587, 6379, 27017}
)
DEVELOPMENT_PORTS = frozenset({3000, 5000, 8000})

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    587: "SMTP Submission",
    1433: "Microsoft SQL Server",
    3000: "開発用Webサーバー",
    3306: "MySQL",
    3389: "RDP",
    5000: "開発用Webサーバー",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "開発用Webサーバー",
    27017: "MongoDB",
}

RECOMMENDATIONS = {
    21: "FTP は平文です。必要なら FTPS / SFTP へ移行し、匿名ログインの可否を確認してください。",
    22: "公開が必要な送信元だけに制限し、鍵認証とパスワード認証の無効化を検討してください。",
    25: "中継許可と認証の要否を確認し、必要なら送信元を制限してください。",
    587: "送信元の制限と認証の要否を確認してください。",
    1433: "公開が必要な送信元だけに制限し、認証方式を確認してください。",
    3000: "開発用サーバーが本番公開されていないか確認し、不要なら停止してください。",
    3306: "公開が必要な送信元だけに制限し、認証と接続元制限を確認してください。",
    3389: "接続元を制限するか VPN 経由にし、多要素認証を検討してください。",
    5000: "開発用サーバーが本番公開されていないか確認し、不要なら停止してください。",
    5432: "公開が必要な送信元だけに制限し、認証方式を確認してください。",
    6379: "外部公開を止めるか、認証と bind 先を制限してください。",
    8000: "開発用サーバーが本番公開されていないか確認し、不要なら停止してください。",
    27017: "外部公開を止めるか、認証と接続元制限を確認してください。",
}

GENERIC_RECOMMENDATION = (
    "実際に待ち受けているサービスと公開の必要性を確認し、"
    "不要な場合は停止するか接続元を制限してください。"
)

NO_PORT_TITLE = "設定済みポートに接続できませんでした"

SERVICE_PROBE_PORTS = frozenset({21, 22, 25, 3306, 587, 6379})
PROTOCOLS = {21: "FTP", 22: "SSH", 25: "SMTP", 587: "SMTP Submission",
             3306: "MySQL", 6379: "Redis"}
REDIS_PING = b"*1\r\n$4\r\nPING\r\n"
MAX_PROTOCOL_RESPONSE_BYTES = 4096
MAX_BANNER_CHARS = 200


def _scheduler(timeout: float) -> Scheduler:
    instance = Scheduler(Budgets(per_host_interval=0.001), scope=lambda url: True)
    instance.http_timeout = lambda: (timeout, timeout)
    instance.start()
    return instance


def _severity_for(port: int, scope: str | None) -> str:
    if scope == "LOOPBACK":
        return "INFO"
    if port in SENSITIVE_PORTS or port in DEVELOPMENT_PORTS:
        return "LOW"
    return "INFO"


def _evidence(entry: dict, target_url: str) -> str:
    host = entry.get("host") or urlparse(target_url).hostname or "unknown"
    lines = [
        f"Host: {host}",
        f"Port: {entry['port']}",
        f"Peer: {entry.get('peer') or 'unknown'}",
        f"Network scope: {entry.get('scope') or 'UNKNOWN'}",
        "Identification: TCP connect only (service not confirmed)",
    ]
    if entry.get("banner"):
        lines.append(f"Banner (unverified): {entry['banner']}")
    lines.append(f"Target: {target_url}")
    return "\n".join(lines)


def _recv_limited_line(conn, limit=512):
    data = bytearray()
    while len(data) < limit:
        chunk = conn.recv(min(128, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    return bytes(data[:limit])


def _recv_exact(conn, size):
    if size < 0 or size > MAX_PROTOCOL_RESPONSE_BYTES:
        return b""
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _safe_banner_text(raw, max_chars=MAX_BANNER_CHARS):
    text = raw.decode("utf-8", errors="replace")
    text = "".join(c for c in text if c in "\t" or (ord(c) >= 32 and ord(c) != 127))
    return text.strip()[:max_chars]


def probe_service_banner(host: str, port: int, timeout: float = 1.0) -> dict | None:
    """非 HTTP サービスの初期応答を安全な範囲で見る。

    SSH / FTP / SMTP はサーバーが先に送る分だけ、MySQL はハンドシェイクだけ、
    Redis は読み取り専用の PING を1回だけ。認証情報は送らない。
    """
    protocol = PROTOCOLS.get(port)
    if not protocol:
        return None

    timeout = max(0.25, min(float(timeout), 2.0))
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)

            if port in (21, 22, 25, 587):
                text = _safe_banner_text(_recv_limited_line(conn, 512))
                if not text:
                    return None
                code = {
                    21: "FTP_GREETING_OBSERVED",
                    22: "SSH_BANNER_OBSERVED",
                    25: "SMTP_GREETING_OBSERVED",
                    587: "SMTP_GREETING_OBSERVED",
                }[port]
                return {
                    "protocol": protocol,
                    "code": code,
                    "label": f"{protocol} の初期応答を観測（未検証）",
                    "evidence": text,
                    "note": "応答文字列は偽装可能で、製品の同一性は確定できません。",
                }

            if port == 3306:
                header = _recv_exact(conn, 4)
                if len(header) < 4:
                    return None
                length = header[0] | (header[1] << 8) | (header[2] << 16)
                text = _safe_banner_text(_recv_exact(conn, length))
                if not text:
                    return None
                return {
                    "protocol": protocol,
                    "code": "MYSQL_HANDSHAKE_OBSERVED",
                    "label": "MySQL の初期ハンドシェイクを観測（未検証）",
                    "evidence": text,
                    "note": "認証パケットは送っていません。",
                }

            conn.sendall(REDIS_PING)
            text = _safe_banner_text(_recv_limited_line(conn, 512))
            if not text:
                return None
            code = ("REDIS_AUTH_REQUIRED_RESPONSE_OBSERVED"
                    if "NOAUTH" in text.upper()
                    else "REDIS_PING_RESPONSE_OBSERVED")
            return {
                "protocol": protocol,
                "code": code,
                "label": "Redis の PING 応答を観測",
                "evidence": text,
                "note": "読み取り専用の PING を1回だけ送っています。",
            }
    except OSError:
        return None


def _port_finding(entry: dict, target_url: str, probe: dict | None = None) -> dict:
    port = entry["port"]
    scope = entry.get("scope")
    name = SERVICE_NAMES.get(port) or entry.get("conventional") or "不明"
    evidence = _evidence(entry, target_url)
    if probe is not None:
        evidence += (
            f"\nIdentification: {probe['code']}"
            f"\nService response (unverified): {probe['evidence']}"
            f"\nNote: {probe['note']}"
        )
    return {
        "type": "PORT_SCAN",
        "subtype": "TCP_PORT_OPEN",
        "severity": _severity_for(port, scope),
        "title": f"ポート {port} で TCP 接続できました（{name} の可能性）",
        "url": target_url,
        "description": (
            "TCP 接続が成立したことだけを確認しています。"
            "待ち受けているサービスは応答内容からは確定できません。"
        ),
        "evidence": evidence,
        "recommendation": RECOMMENDATIONS.get(port, GENERIC_RECOMMENDATION),
    }


def _tls_finding(observation, target_url: str) -> dict | None:
    data = observation.data
    if data.get("verification") != "FAILED":
        return None

    certificate = data.get("certificate") or {}
    scope = certificate.get("scope")
    return {
        "type": "TLS",
        "subtype": "TLS_CERTIFICATE_VERIFICATION_FAILED",
        "severity": "INFO" if scope == "LOOPBACK" else "MEDIUM",
        "title": "TLS 証明書を検証できませんでした",
        "url": target_url,
        "description": (
            "証明書の検証に失敗しました。原因はホスト名不一致・期限切れ・"
            "未知の CA のいずれかで、ここでは特定できません。"
        ),
        "evidence": (
            f"Protocol: {data.get('protocol')}\n"
            f"Cipher: {data.get('cipher')}\n"
            f"Verification: {data.get('verification_error') or 'FAILED'}"
        ),
        "recommendation": (
            "原因を特定して証明書を修正してください。"
            "ホスト名不一致なら更新、未知の CA ならチェーンを見直します。"
        ),
    }


def check_web_ports(target_url: str, timeout: float = 0.5) -> list[dict]:
    """固定リストのポートを試し、旧形式の Finding を返す。"""
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL の形式が不正です")
    if parsed.username or parsed.password:
        raise ValueError("認証情報付きの URL は対象外です")

    host = parsed.hostname
    scheduler = _scheduler(timeout)
    observation = scan.collect(host, scheduler)

    findings: list[dict] = []
    for entry in observation.data.get("ports", []):
        if entry["state"] != "open":
            continue

        entry["host"] = host
        service_probe = None
        if entry["port"] in SERVICE_PROBE_PORTS:
            service_probe = probe_service_banner(host, entry["port"], timeout=1.0)
        findings.append(_port_finding(entry, target_url, service_probe))

        if entry["port"] in scan.TLS_PORTS:
            probe = tls.collect(f"https://{host}:{entry['port']}/", scheduler)
            finding = _tls_finding(probe, target_url)
            if finding is not None:
                findings.append(finding)

    if not findings:
        return [{
            "type": "PORT_SCAN",
            "subtype": "NO_CONFIGURED_PORT_DETECTED",
            "severity": "INFO",
            "title": NO_PORT_TITLE,
            "url": target_url,
            "description": "固定リストのポートに接続できませんでした。",
            "evidence": "Identification: no TCP connect on the configured port list",
            "recommendation": "公開しているポートがある場合、一覧を見直してください。",
        }]
    return findings