"""TLS ハンドシェイクの Collector。

観測のみ。判定はしない。

方針:
    - 検証状態と通信の成否を分けて持つ。検証失敗でも通信は成立しうる
    - 検証失敗時は検証なしで 1 回だけ再試行する。ただし FAILED のまま保持する
    - 証明書は期限・SAN・チェーン長だけを見る
    - socket / ssl を直接使うが、同時実行とレートは Scheduler の枠で統制する

TLS プロトコル版と暗号スイートはハンドシェイク後にしか取れないため、
接続を維持したまま取得して閉じる。
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from engine.observations import Observation

COLLECTOR = "tls"

DEFAULT_TIMEOUT = 6.0

VERIFIED = "VERIFIED"
FAILED = "FAILED"

Handshake = Callable[..., dict]


def _parse_cert_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _certificate_details(sock) -> dict:
    der = sock.getpeercert(binary_form=True)
    cert = sock.getpeercert() or {}

    subject = {key: value for item in cert.get("subject", ()) for key, value in item}
    issuer = {key: value for item in cert.get("issuer", ()) for key, value in item}
    san = [value for kind, value in cert.get("subjectAltName", ()) if kind.lower() == "dns"]

    not_after = _parse_cert_time(cert.get("notAfter", ""))
    days_left = None
    if not_after is not None:
        days_left = (not_after - datetime.now(timezone.utc)).days

    return {
        "present": der is not None,
        "der_length": len(der) if der else 0,
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "san": san,
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "days_until_expiry": days_left,
    }


def _handshake(host: str, port: int, *, verify: bool, timeout: float) -> dict:
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            details = _certificate_details(tls)
            details["protocol"] = tls.version()
            cipher = tls.cipher()
            details["cipher"] = cipher[0] if cipher else None
            details["cipher_bits"] = cipher[2] if cipher else None
            return details


def attempt(
    handshake: Handshake,
    host: str,
    port: int,
    timeout: float,
) -> tuple[dict, str, str | None, bool]:
    """検証ありで試し、検証失敗なら検証なしで1回だけ再試行する。

    戻り値は ``(details, verification, error, retried)``。
    再試行しても verification は FAILED のまま返す。
    """
    try:
        return handshake(host, port, verify=True, timeout=timeout), VERIFIED, None, False
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, "verify_message", "") or str(exc)
        error = f"{type(exc).__name__}: {message}"
        details = handshake(host, port, verify=False, timeout=timeout)
        return details, FAILED, error, True


def collect(
    url: str,
    scheduler,
    *,
    port: int | None = None,
    connect: Handshake | None = None,
) -> Observation:
    """TLS を観測する。HTTP ではなく直接ハンドシェイクする。"""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return Observation.error(COLLECTOR, url, "ホスト名を取得できません")

    if parts.scheme != "https":
        return Observation.skipped(COLLECTOR, url, "https ではないため TLS は対象外")

    target_port = port or parts.port or 443
    handshake = connect or _handshake

    try:
        scheduler.check_cancel()
        scheduler.check_time()
        scheduler.check_scope(url)
        scheduler.reserve("request")

        with scheduler.slot(host):
            timeout = min(scheduler.http_timeout()[1], DEFAULT_TIMEOUT)
            details, verification, error, retried = attempt(
                handshake, host, target_port, timeout
            )
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, "verify_message", "") or str(exc)
        return Observation.error(COLLECTOR, url, f"証明書検証に失敗: {message}")
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return Observation.error(COLLECTOR, url, f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001
        return Observation.error(COLLECTOR, url, f"{type(exc).__name__}: {exc}")

    return Observation.ok(
        COLLECTOR,
        url,
        {
            "verification": verification,
            "verification_error": error,
            "retried_without_verification": retried,
            "protocol": details.get("protocol"),
            "cipher": details.get("cipher"),
            "cipher_bits": details.get("cipher_bits"),
            "certificate": {
                key: value
                for key, value in details.items()
                if key not in ("protocol", "cipher", "cipher_bits")
            },
            "port": target_port,
        },
    )