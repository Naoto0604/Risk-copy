import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


# 検査対象は一般的なTCPサービスの固定リストに限定する。
# 実際にどのサービスが動いているかは、ポート番号だけでは断定しない。
SERVICE_PORTS = {
    21: "FTP（ファイル転送）",
    22: "SSH（リモート管理）",
    23: "Telnet（リモート管理）",
    25: "SMTP（メール転送）",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB（ファイル共有）",
    1433: "Microsoft SQL Server",
    3000: "開発用Webサーバー",
    3306: "MySQL",
    3389: "RDP（リモートデスクトップ）",
    5000: "開発用Webサーバー",
    5432: "PostgreSQL",
    587: "SMTP Submission（メール送信）",
    6379: "Redis",
    8000: "開発用Webサーバー",
    8080: "代替HTTP",
    8443: "代替HTTPS",
    27017: "MongoDB",
}

# 旧定数名を使うコードとの互換性を維持する。
WEB_PORTS = SERVICE_PORTS
TLS_PORTS = {443, 8443}
HTTP_PORTS = {80, 3000, 5000, 8000, 8080}
DEVELOPMENT_PORTS = {3000, 5000, 8000}

# TCP接続だけでは実サービスが確認できないため、これらは「要確認」として
# LOWで報告する。ポートが開いていることだけで脆弱性とは断定しない。
SENSITIVE_SERVICE_PORTS = {
    21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 587, 6379, 27017
}

SERVICE_RECOMMENDATIONS = {
    25: (
        "SMTPサーバーの公開が必要か確認してください。オープンリレーになっていないこと、"
        "不正な中継の制限、メール送信ポリシー、必要に応じたTLS設定を管理者が確認してください。"
    ),
    587: (
        "メール送信（Submission）サービスの必要性を確認し、認証とTLSを適切に要求してください。"
        "利用者・接続元を必要な範囲に制限してください。"
    ),
    21: (
        "実際にFTPが稼働しているか確認してください。不要なら停止してください。"
        "必要な場合は、暗号化されたSFTPまたはFTPSを検討し、接続元を制限してください。"
    ),
    22: (
        "SSHなどの管理サービスが必要か確認し、管理者に限定して接続元を制限してください。"
        "鍵認証、アカウント保護、不要なログイン方法の無効化も確認してください。"
    ),
    23: (
        "実際にTelnetが稼働している場合、通信が暗号化されない可能性があります。"
        "不要なら停止し、リモート管理にはSSHなどの暗号化された方式を使用してください。"
    ),
    445: (
        "SMBなどのファイル共有サービスが必要か確認し、信頼できるネットワークに限定してください。"
        "ファイアウォール設定と、古いSMBプロトコルの無効化を確認してください。"
    ),
    1433: (
        "データベースへの接続が必要な送信元だけに制限してください。"
        "インターネットへの直接公開を避け、認証と暗号化の設定を確認してください。"
    ),
    3306: (
        "MySQLなどのデータベースへの接続元をアプリケーションサーバー等に限定してください。"
        "不要な外部公開を避け、認証と暗号化の設定を確認してください。"
    ),
    3389: (
        "RDPなどのリモートデスクトップ接続が必要か確認し、VPNや管理用ネットワークなどに限定してください。"
        "強固な認証と多要素認証の利用も検討してください。"
    ),
    5432: (
        "PostgreSQLなどのデータベースへの接続元を必要なサーバーに限定してください。"
        "不要な外部公開を避け、認証と暗号化の設定を確認してください。"
    ),
    6379: (
        "Redisなどのデータストアへの接続を信頼できるホストに限定してください。"
        "不要な外部公開を避け、認証・アクセス制御・ファイアウォール設定を確認してください。"
    ),
    27017: (
        "MongoDBなどのデータベースへの接続元を必要なホストに限定してください。"
        "不要な外部公開を避け、認証・アクセス制御・暗号化設定を確認してください。"
    ),
}


def _format_certificate_name(name):
    """ssl.getpeercert()形式のSubject/Issuerを読みやすい文字列にする。"""
    parts = []
    for relative_name in name or ():
        for key, value in relative_name:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or None


def _format_certificate_time(value):
    """証明書日時をUTC ISO 8601形式に変換する。"""
    if not value:
        return None
    try:
        timestamp = ssl.cert_time_to_seconds(value)
        return (
            datetime.fromtimestamp(timestamp, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        return value


def _add_optional_der_certificate_details(der_certificate, result):
    """cryptographyがインストールされていれば、DER証明書の詳細も取得する。

    cryptographyは必須依存ではない。未インストールの場合も、TLS情報と
    検証エラーの記録はそのまま機能する。
    """
    if not der_certificate:
        return

    try:
        from cryptography import x509
    except ImportError:
        return

    try:
        certificate = x509.load_der_x509_certificate(der_certificate)
        result["certificate_subject"] = (
            certificate.subject.rfc4514_string() or None
        )
        result["certificate_issuer"] = (
            certificate.issuer.rfc4514_string() or None
        )

        not_before = getattr(certificate, "not_valid_before_utc", None)
        if not_before is None:
            not_before = certificate.not_valid_before.replace(
                tzinfo=timezone.utc
            )
        not_after = getattr(certificate, "not_valid_after_utc", None)
        if not_after is None:
            not_after = certificate.not_valid_after.replace(
                tzinfo=timezone.utc
            )

        result["certificate_not_before"] = not_before.isoformat().replace(
            "+00:00", "Z"
        )
        result["certificate_not_after"] = not_after.isoformat().replace(
            "+00:00", "Z"
        )

        try:
            san_extension = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            result["certificate_san"] = ", ".join(
                str(name)
                for name in san_extension.value
            ) or None
        except x509.ExtensionNotFound:
            result["certificate_san"] = None
    except (ValueError, TypeError):
        # 証明書をデコードできなくても、検査全体は継続する。
        return


def _collect_tls_socket_details(tls_socket, result):
    """TLSソケットからネゴシエーション情報と取得可能な証明書情報を収集する。"""
    result["tls_version"] = tls_socket.version()

    cipher = tls_socket.cipher()
    if cipher:
        cipher_name, _protocol, bits = cipher
        result["cipher_suite"] = f"{cipher_name} ({bits} bits)"

    certificate = tls_socket.getpeercert()
    if certificate:
        result["certificate_subject"] = _format_certificate_name(
            certificate.get("subject")
        )
        result["certificate_issuer"] = _format_certificate_name(
            certificate.get("issuer")
        )
        result["certificate_not_before"] = _format_certificate_time(
            certificate.get("notBefore")
        )
        result["certificate_not_after"] = _format_certificate_time(
            certificate.get("notAfter")
        )
        san_values = certificate.get("subjectAltName", ())
        result["certificate_san"] = ", ".join(
            f"{name_type}:{name_value}"
            for name_type, name_value in san_values
        ) or None

    der_certificate = tls_socket.getpeercert(binary_form=True)
    if der_certificate:
        result["certificate_sha256"] = hashlib.sha256(
            der_certificate
        ).hexdigest()
        # 検証エラーがある接続ではgetpeercert()が空辞書になるため、
        # 任意依存があればDERから証明書情報を補足する。
        if not result.get("certificate_subject"):
            _add_optional_der_certificate_details(der_certificate, result)


def probe_tls_service(host, port, timeout=2.0):
    """TLSポートを検査し、TLS情報と証明書の検証結果を返す。

    検証済みの接続を優先する。証明書検証に失敗した場合だけ、診断情報を
    収集する目的で検証を無効にした接続を再試行する。この2回目の接続は
    信頼できる接続としては扱わず、検証結果はFAILEDのまま記録する。
    """
    if port not in TLS_PORTS:
        raise ValueError("TLS確認の対象ポートではありません")
    if not host:
        raise ValueError("TLS確認のホスト名がありません")

    timeout = max(float(timeout), 1.0)
    result = {
        "verification": "NOT_COMPLETED",
        "verification_error": None,
        "verification_code": None,
        "verification_message": None,
        "tls_version": None,
        "cipher_suite": None,
        "certificate_subject": None,
        "certificate_issuer": None,
        "certificate_not_before": None,
        "certificate_not_after": None,
        "certificate_san": None,
        "certificate_sha256": None,
        "error": None,
    }

    verified_context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            raw_socket.settimeout(timeout)
            with verified_context.wrap_socket(
                raw_socket,
                server_hostname=host,
            ) as tls_socket:
                _collect_tls_socket_details(tls_socket, result)
                result["verification"] = "PASSED"
                return result

    except ssl.SSLCertVerificationError as exc:
        result["verification"] = "FAILED"
        result["verification_error"] = str(exc)
        result["verification_code"] = getattr(exc, "verify_code", None)
        result["verification_message"] = getattr(exc, "verify_message", None)

        # 証明書検証の失敗理由を保持したまま、TLSネゴシエーション情報と
        # ピア証明書を観測する。情報取得用であり、検証成功を意味しない。
        try:
            diagnostic_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            diagnostic_context.check_hostname = False
            diagnostic_context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (host, port),
                timeout=timeout,
            ) as raw_socket:
                raw_socket.settimeout(timeout)
                with diagnostic_context.wrap_socket(
                    raw_socket,
                    server_hostname=host,
                ) as tls_socket:
                    _collect_tls_socket_details(tls_socket, result)
        except (OSError, ssl.SSLError, ValueError) as probe_error:
            result["error"] = str(probe_error)

        return result

    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = str(exc)
        return result




# アプリケーション応答の取得は、認証情報や更新系コマンドを送らず、
# バナー・初期ハンドシェイク・Redisの読み取り専用PINGだけに限定する。
SERVICE_PROBE_PORTS = {21, 22, 25, 3306, 587, 6379}
MAX_PROTOCOL_RESPONSE_BYTES = 4096
MAX_BANNER_CHARS = 256


def _recv_limited_line(sock, limit=512):
    """LFまで、または上限に達するまで1行を限定サイズで受信する。"""
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(min(128, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    return bytes(data[:limit])


def _recv_exact(sock, size):
    """指定サイズまで受信する。接続が閉じたら受信済みデータを返す。"""
    if size < 0 or size > MAX_PROTOCOL_RESPONSE_BYTES:
        return b""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _safe_banner_text(raw, max_chars=MAX_BANNER_CHARS):
    """制御文字や過大な応答をEvidenceに流さないように整形する。"""
    text = raw.decode("utf-8", errors="replace")
    text = "".join(
        char for char in text
        if char in "\t" or (ord(char) >= 32 and ord(char) != 127)
    )
    return text.strip()[:max_chars]


def probe_service_banner(host, port, timeout=1.0):
    """非HTTPサービスの初期応答を安全な範囲で確認する。

    - SSH/FTP/SMTP: サーバーが先に送る初期バナー・挨拶のみ受信
    - MySQL: 初期ハンドシェイクパケットのみ受信。認証情報は送信しない
    - Redis: 読み取り専用の PING を1回送信。キーの読取・変更はしない

    戻り値のバナーは観測したプロトコル応答であり、製品情報の真正性を保証しない。
    認識できない応答や通信エラーの場合は None を返す。
    """
    protocol_by_port = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        3306: "MySQL",
        587: "SMTP Submission",
        6379: "Redis",
    }
    protocol = protocol_by_port.get(port)
    if not protocol:
        return None

    timeout = max(0.25, min(float(timeout), 2.0))
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)

            if port in (21, 22, 25, 587):
                raw = _recv_limited_line(conn, limit=512)
                text = _safe_banner_text(raw)
                if not text:
                    return None

                if port == 22 and text.startswith("SSH-"):
                    code = "SSH_BANNER_OBSERVED"
                    label = "SSH識別バナーを観測。製品・バージョン情報は未検証。"
                    evidence = f"Observed SSH banner (unverified): {text}"
                elif port == 21 and text[:3] == "220":
                    code = "FTP_GREETING_OBSERVED"
                    label = "FTP形式の220初期応答を観測。製品情報は未検証。"
                    evidence = f"Observed FTP greeting (unverified): {text}"
                elif port in (25, 587) and text[:3] == "220":
                    code = "SMTP_GREETING_OBSERVED"
                    label = "SMTP形式の220初期応答を観測。製品情報は未検証。"
                    evidence = f"Observed SMTP greeting (unverified): {text}"
                else:
                    return None

                return {
                    "protocol": protocol,
                    "code": code,
                    "label": label,
                    "note": (
                        "プロトコル形式の初期応答を観測しました。バナーは任意の文字列であり、"
                        "偽装・省略される可能性があります。製品やバージョンの確定情報として扱いません。"
                    ),
                    "evidence": evidence,
                    "observed_value": text,
                }

            if port == 3306:
                header = _recv_exact(conn, 4)
                if len(header) != 4:
                    return None
                packet_length = int.from_bytes(header[:3], "little")
                if packet_length < 2 or packet_length > MAX_PROTOCOL_RESPONSE_BYTES:
                    return None
                payload = _recv_exact(conn, packet_length)
                if len(payload) < 2 or payload[0] != 0x0A:
                    return None
                end = payload.find(b"\x00", 1)
                if end < 0:
                    return None
                server_version = _safe_banner_text(payload[1:end])
                if not server_version:
                    return None
                return {
                    "protocol": protocol,
                    "code": "MYSQL_HANDSHAKE_OBSERVED",
                    "label": "MySQLプロトコルの初期ハンドシェイクを観測。製品情報は未検証。",
                    "note": (
                        "MySQL互換プロトコルの初期ハンドシェイクを観測しました。"
                        "バージョン文字列はサーバー側の応答であり、偽装可能なため未検証情報として扱います。"
                    ),
                    "evidence": f"Observed MySQL server version string (unverified): {server_version}",
                    "observed_value": server_version,
                }

            if port == 6379:
                # Redis RESP PING は読み取り専用で、キーや設定を変更しない。
                conn.sendall(b"*1\r\n$4\r\nPING\r\n")
                raw = conn.recv(512)
                text = _safe_banner_text(raw)
                upper = text.upper()
                if upper.startswith("+PONG"):
                    code = "REDIS_PING_RESPONSE_OBSERVED"
                    label = "Redis互換のRESP PONG応答を観測。製品情報は未検証。"
                elif upper.startswith("-NOAUTH") or upper.startswith("-DENIED"):
                    code = "REDIS_AUTH_REQUIRED_RESPONSE_OBSERVED"
                    label = "Redis互換の認証・アクセス制御エラー応答を観測。製品情報は未検証。"
                else:
                    return None
                return {
                    "protocol": protocol,
                    "code": code,
                    "label": label,
                    "note": (
                        "Redis互換のRESP応答を観測しました。PINGは読み取り専用ですが、"
                        "応答文字列だけで実際の製品を確定することはできません。"
                    ),
                    "evidence": f"Observed Redis-compatible PING response (unverified): {text}",
                    "observed_value": text,
                }

    except (OSError, ssl.SSLError, ValueError, TimeoutError):
        return None

    return None

def classify_tls_verification_failure(tls_info):
    """証明書検証エラーを原因別に分類し、説明と修正案を返す。

    OpenSSL/Pythonが返す検証コードとメッセージを優先して分類する。
    判定できないケースは汎用の検証失敗として扱い、根拠なく断定しない。
    """
    error_text = " ".join(
        str(value)
        for value in (
            tls_info.get("verification_error"),
            tls_info.get("verification_message"),
            tls_info.get("error"),
        )
        if value
    ).lower()
    verification_code = tls_info.get("verification_code")

    # OpenSSL X509 verify codes: 9=not yet valid, 10=expired,
    # 18=self-signed leaf, 19=self-signed chain, 20/21=issuer/chain errors,
    # 62=hostname mismatch. Text checks cover common runtime variations.
    if verification_code == 10 or "certificate has expired" in error_text or "expired certificate" in error_text:
        return {
            "subtype": "TLS_CERTIFICATE_EXPIRED",
            "title": "TLS証明書の有効期限が切れています",
            "description": "証明書の検証で有効期限切れが報告されました。対象サーバーの証明書の期限と更新状況を確認してください。",
            "recommendation": "正しいホスト名用の証明書を有効期限内のものへ更新し、サーバーに正しい証明書チェーンを設定してください。検査対象のシステム時刻も確認してください。",
        }

    if verification_code == 9 or "certificate is not yet valid" in error_text or "not yet valid" in error_text:
        return {
            "subtype": "TLS_CERTIFICATE_NOT_YET_VALID",
            "title": "TLS証明書の有効期間がまだ始まっていません",
            "description": "証明書の検証で、有効期間開始前であることが報告されました。証明書の開始日時とサーバー・診断端末の時刻を確認してください。",
            "recommendation": "証明書の有効期間を確認し、サーバーと診断端末のシステム時刻を正しく同期してください。",
        }

    if (
        verification_code == 62
        or "hostname mismatch" in error_text
        or "ip address mismatch" in error_text
        or "doesn't match" in error_text
        or "does not match" in error_text
    ):
        return {
            "subtype": "TLS_HOSTNAME_MISMATCH",
            "title": "TLS証明書のホスト名が接続先と一致しません",
            "description": "接続に使用したホスト名またはIPアドレスが、証明書のSAN等に含まれる識別子と一致しないことが報告されました。接続先URLが意図したホスト名であるか確認してください。",
            "recommendation": "対象ホスト名をSANに含む正しい証明書を設定してください。IPアドレスでアクセスする場合は、証明書にそのIPアドレスのSANが必要です。意図したホスト名で検査していることも確認してください。",
        }

    if "self-signed certificate in certificate chain" in error_text:
        return {
            "subtype": "TLS_UNTRUSTED_ISSUER",
            "title": "TLS証明書チェーンの発行元を信頼できません",
            "description": "証明書チェーン内の自己署名証明書が信頼されていないか、信頼チェーンを構築できないことが報告されました。内部CAを利用する環境では、信頼設定も確認が必要です。",
            "recommendation": "サーバーが正しい中間証明書を送信しているか確認してください。内部CAを利用する場合は、管理された手順で診断環境の信頼ストアに正しいCA証明書を登録してください。",
        }

    if (
        verification_code == 18
        or "self-signed certificate" in error_text
        or "self signed certificate" in error_text
    ):
        return {
            "subtype": "TLS_SELF_SIGNED_CERTIFICATE",
            "title": "TLS証明書が自己署名証明書です",
            "description": "証明書検証で自己署名証明書が報告されました。ローカルテストや管理された内部環境では意図的な場合がありますが、一般公開サービスでは利用者が通常信頼できない可能性があります。",
            "recommendation": "公開サービスでは信頼されたCAから適切な証明書を発行して設定してください。内部テストの場合は、自己署名証明書を意図して使用しているかを確認し、必要に応じて管理されたテスト用CAを信頼させてください。",
        }

    if (
        verification_code in {20, 21}
        or "unable to get local issuer certificate" in error_text
        or "unable to verify the first certificate" in error_text
        or "unknown ca" in error_text
        or "issuer certificate" in error_text
    ):
        return {
            "subtype": "TLS_UNTRUSTED_ISSUER",
            "title": "TLS証明書の発行元またはチェーンを検証できません",
            "description": "証明書の発行元を信頼できない、または証明書チェーンを構築できないという検証結果です。中間証明書の不足や、診断端末の信頼ストアが原因の場合があります。",
            "recommendation": "サーバー証明書に必要な中間証明書が設定されているか確認してください。内部CAを使用している場合は、そのCAが診断端末の信頼ストアで適切に信頼されているかを確認してください。",
        }

    return {
        "subtype": "TLS_CERTIFICATE_VERIFICATION_FAILED",
        "title": "TLS証明書を検証できませんでした",
        "description": "TLS証明書の検証に失敗しましたが、エラーの原因を自動では特定できませんでした。証明書・ホスト名・有効期間・信頼チェーン・診断端末の時刻を確認してください。",
        "recommendation": "詳細な検証エラーを確認し、証明書のホスト名、有効期間、発行元と中間証明書、診断端末の信頼ストアを確認してください。",
    }


def probe_http_service(host, port, timeout=0.5):
    """HTTP応答からステータス行とServerヘッダーを取得する。"""
    if port in TLS_PORTS:
        return None, None

    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            host_header = f"[{host}]" if ":" in host else host
            if port != 80:
                host_header = f"{host_header}:{port}"

            request_data = (
                "HEAD / HTTP/1.0\r\n"
                f"Host: {host_header}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii", errors="ignore")
            conn.sendall(request_data)
            raw_response = conn.recv(4096)

        if not isinstance(raw_response, bytes):
            return None, None
        response_text = raw_response.decode("iso-8859-1", errors="replace")
    except (OSError, ValueError):
        return None, None

    lines = response_text.splitlines()
    status_line = lines[0] if lines and lines[0].startswith("HTTP/") else None
    server_header = None

    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server_header = line.split(":", 1)[1].strip()
            break

    return status_line, server_header


def classify_network_scope(address_or_host):
    """接続したIPアドレスのネットワーク区分を返す。

    DNS名はここで別途解決しない。実際のTCP接続で取得したpeer IPを優先し、
    取得できなければlocalhostやIPリテラルだけを分類する。
    """
    if not address_or_host:
        return "UNKNOWN"

    text = str(address_or_host).strip()
    lower_text = text.lower().rstrip(".")
    if lower_text == "localhost" or lower_text.endswith(".localhost"):
        return "LOOPBACK"

    # IPv6 scope id (e.g. fe80::1%12) is not part of the address literal.
    text = text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "UNKNOWN"

    if getattr(address, "ipv4_mapped", None) is not None:
        address = address.ipv4_mapped

    if address.is_loopback:
        return "LOOPBACK"
    if address.is_link_local:
        return "LINK_LOCAL"

    # Use explicit private ranges so documentation/special-use IPs are not
    # mislabeled as ordinary RFC1918/ULA private targets.
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
    )
    if any(address.version == network.version and address in network for network in private_networks):
        return "PRIVATE"
    if address.is_multicast:
        return "MULTICAST"
    if address.is_unspecified:
        return "UNSPECIFIED"
    if address.is_global:
        return "PUBLIC"
    return "SPECIAL_USE"


NETWORK_SCOPE_LABELS = {
    "LOOPBACK": "ループバック（検査端末自身）",
    "PRIVATE": "プライベートアドレス（内部ネットワーク）",
    "LINK_LOCAL": "リンクローカルアドレス",
    "PUBLIC": "グローバルIPアドレス",
    "MULTICAST": "マルチキャストアドレス",
    "UNSPECIFIED": "未指定アドレス",
    "SPECIAL_USE": "予約済み・特殊用途アドレス",
    "UNKNOWN": "不明（接続先IPを確認できず）",
}


def _get_peer_ip(connection):
    """socketから実際に接続したpeer IPを取得する。取得不能ならNone。"""
    try:
        peer = connection.getpeername()
    except (AttributeError, OSError, TypeError):
        return None
    if isinstance(peer, tuple) and peer and isinstance(peer[0], str):
        return peer[0].split("%", 1)[0]
    return None


def _scope_context(scope):
    """到達性について、観測事実と未確認事項を区別した説明を返す。"""
    label = NETWORK_SCOPE_LABELS.get(scope, NETWORK_SCOPE_LABELS["UNKNOWN"])
    if scope == "LOOPBACK":
        note = (
            "接続先はループバックアドレスで、検査を実行している端末自身を指します。"
            "この結果は別ホストや外部ネットワークからの到達可能性を示しません。"
        )
    elif scope == "PRIVATE":
        note = (
            "接続先はプライベートアドレスです。検査端末から到達できたことは確認しましたが、"
            "インターネットからの到達可能性や、他の端末からの到達可能性までは証明しません。"
        )
    elif scope == "LINK_LOCAL":
        note = (
            "接続先はリンクローカルアドレスです。到達性は同一リンク等のネットワーク条件に依存し、"
            "インターネットからの公開を示すものではありません。"
        )
    elif scope == "PUBLIC":
        note = (
            "接続に使用したIPアドレスはグローバルアドレスに分類されます。"
            "ただし、この検査端末から接続できたことだけでは、インターネット上の全地点から"
            "到達できることや、ファイアウォール設定全体を証明しません。"
        )
    elif scope == "UNKNOWN":
        note = (
            "接続先IPアドレスを取得できなかったため、ローカル・内部・グローバルの区分は未確定です。"
            "外部公開の有無は、この結果だけでは判断できません。"
        )
    else:
        note = (
            "接続先は特殊用途アドレスに分類されます。通常の公開アドレスとして扱わず、"
            "診断環境とルーティング設定を確認してください。"
        )
    return label, note


def _service_identification(port, status_line, server_header, tls_info, service_probe=None):
    """サービスの特定度を過大評価せず、検査で観測した事実を要約する。"""
    if service_probe:
        return (
            service_probe.get("code", "PROTOCOL_RESPONSE_OBSERVED"),
            service_probe.get("label", "プロトコル応答を観測。製品情報は未検証。"),
            service_probe.get("note", "観測した応答は偽装可能なため未検証情報として扱います。"),
        )
    if port in TLS_PORTS and tls_info and tls_info.get("tls_version"):
        verification = tls_info.get("verification", "NOT_COMPLETED")
        return (
            "TLS_HANDSHAKE_OBSERVED",
            "TLSハンドシェイクを観測。アプリケーションサービスの実体は未特定。",
            "TLSプロトコルは確認できました。証明書検証結果は別途評価し、"
            "アプリケーションの種類まではこの検査で断定しません。",
        )
    if status_line:
        suffix = "Serverヘッダーも観測" if server_header else "Serverヘッダーは取得できず"
        return (
            "HTTP_RESPONSE_OBSERVED",
            f"HTTP応答を観測。{suffix}。製品名は未検証。",
            "HTTP応答を確認しました。Serverヘッダーはサーバーが返した文字列であり、"
            "偽装できるため、製品やバージョンの確定情報としては扱いません。",
        )
    return (
        "TCP_CONNECTION_ONLY",
        "TCP接続のみ確認。実際のサービスは未確認。",
        "TCP接続が成立したことだけを確認しました。ポート番号から想定されるサービスは"
        "推測にすぎず、実際のサービスや設定は未確認です。",
    )


def _finding_risk_for_port(port, service, scope):
    """ポートの用途候補と観測したアドレス範囲を組み合わせて評価する。"""
    needs_review = port in SENSITIVE_SERVICE_PORTS or port in DEVELOPMENT_PORTS
    if not needs_review:
        return "INFO", f"TCPポート {port} への接続を確認しました"

    if scope == "LOOPBACK":
        return (
            "INFO",
            f"ローカル環境で {service} に使われることがあるTCPポート {port} を確認しました（要確認）",
        )

    return (
        "LOW",
        f"{service} に使われることがあるTCPポート {port} への接続を確認しました（要確認）",
    )


def check_web_ports(target_url, timeout=0.5):
    """固定リストのTCPポートを検査し、観測範囲・確度・対策を含むFindingを返す。

    This function does not claim a service is present from the port number alone.
    A successful TCP connection describes reachability from this scanner only.
    """
    parsed = urlparse(target_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("ポート確認の対象URLが不正です")

    host = parsed.hostname
    open_ports = []

    for port, service in SERVICE_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=timeout) as connection:
                peer_ip = _get_peer_ip(connection)
            scope = classify_network_scope(peer_ip or host)
            open_ports.append((port, service, peer_ip, scope))
        except OSError:
            continue

    findings = []

    for port, service, peer_ip, scope in open_ports:
        tls_info = None

        service_probe = None
        if port in TLS_PORTS:
            tls_info = probe_tls_service(
                host,
                port,
                timeout=max(float(timeout), 1.0),
            )
            status_line, server_header = None, None
        elif port in HTTP_PORTS:
            status_line, server_header = probe_http_service(
                host,
                port,
                timeout=timeout,
            )
        elif port in SERVICE_PROBE_PORTS:
            service_probe = probe_service_banner(
                host,
                port,
                timeout=max(float(timeout), 1.0),
            )
            status_line, server_header = None, None
        else:
            # SMB/RDP/PostgreSQL/MSSQL/MongoDB等にはHTTPデータを送らない。
            status_line, server_header = None, None

        severity, title = _finding_risk_for_port(port, service, scope)
        scope_label, scope_note = _scope_context(scope)
        identification_code, identification_label, confidence_note = _service_identification(
            port, status_line, server_header, tls_info, service_probe
        )

        if port in SENSITIVE_SERVICE_PORTS:
            recommendation = SERVICE_RECOMMENDATIONS[port]
            if scope == "LOOPBACK":
                description = (
                    f"{host} のTCPポート {port} への接続を確認しました。このポートは通常 {service} "
                    "に使われますが、TCP接続だけでは実際のサービスや設定は確認できません。"
                    "接続先がループバックのため、この結果は別ホスト・外部ネットワークからの"
                    "到達可能性を示しません。ローカルサービスとして必要か確認してください。"
                )
            else:
                description = (
                    f"{host} のTCPポート {port} への接続を確認しました。このポートは通常 {service} "
                    "に使われますが、TCP接続だけでは実際のサービスや設定は確認できません。"
                    f"{scope_note} 必要性と接続元制限を確認してください。"
                )
        elif port in DEVELOPMENT_PORTS:
            recommendation = (
                "実際に稼働しているサービスを確認してください。開発用サーバーの場合は、"
                "不要なら停止し、必要な場合も接続元を制限してください。"
            )
            description = (
                f"{host} のTCPポート {port} に接続できました。このポートは開発用サーバーで"
                "使われることがありますが、ポート番号だけでは実際のサービスを確定できません。"
                f"{scope_note} 公開の必要性と接続制限を確認してください。"
            )
        else:
            recommendation = (
                "待ち受けているサービスと公開の必要性を確認してください。"
                "不要なサービスは停止し、必要に応じて接続元を制限してください。"
            )
            description = (
                f"{host} のTCPポート {port} への接続を確認しました。想定用途は {service} です。"
                "ポートが開いていること自体は脆弱性を意味せず、実際のサービスも未確認です。"
                f"{scope_note}"
            )

        evidence_lines = [
            f"Host: {host}",
            f"Port: {port}",
            f"Expected service (port-based guess): {service}",
            f"TCP peer IP: {peer_ip or 'not available'}",
            f"Network scope: {scope} ({scope_label})",
            f"Service identification: {identification_code}",
            f"Identification confidence: {identification_label}",
            "Method: TCP connection",
        ]
        if status_line:
            evidence_lines.append(f"HTTP status: {status_line}")
        if server_header:
            evidence_lines.append(
                f"Server header (unverified banner): {server_header}"
            )
        if service_probe:
            evidence_lines.append(f"Protocol probe: {service_probe.get('protocol', 'unknown')}")
            if service_probe.get("evidence"):
                evidence_lines.append(service_probe["evidence"])
        evidence_lines.append(f"Assessment note: {confidence_note}")

        if tls_info is not None:
            evidence_lines.append(
                f"TLS certificate verification: {tls_info.get('verification', 'NOT_COMPLETED')}"
            )
            for key, label in (
                ("tls_version", "TLS version"),
                ("cipher_suite", "Cipher suite"),
                ("certificate_subject", "Certificate subject"),
                ("certificate_issuer", "Certificate issuer"),
                ("certificate_san", "Certificate subject alternative names"),
                ("certificate_not_before", "Certificate valid from"),
                ("certificate_not_after", "Certificate valid until"),
                ("certificate_sha256", "Certificate SHA-256 fingerprint"),
                ("verification_error", "Certificate verification error"),
                ("verification_code", "Certificate verification code"),
                ("verification_message", "Certificate verification message"),
                ("error", "TLS probe error"),
            ):
                value = tls_info.get(key)
                if value:
                    evidence_lines.append(f"{label}: {value}")

        findings.append({
            "type": "PORT_SCAN",
            "subtype": "TCP_PORT_OPEN",
            "severity": severity,
            "title": title,
            "url": target_url,
            "description": description,
            "evidence": "\n".join(evidence_lines),
            "recommendation": recommendation,
        })

        # Certificate validation failures are separate findings. Context matters:
        # a loopback-only service is reported as INFO rather than implying public exposure.
        if tls_info and tls_info.get("verification") == "FAILED":
            tls_evidence = [
                f"Host: {host}",
                f"Port: {port}",
                f"TCP peer IP: {peer_ip or 'not available'}",
                f"Network scope: {scope} ({scope_label})",
                "TLS certificate verification: FAILED",
            ]
            for key, label in (
                ("tls_version", "TLS version"),
                ("cipher_suite", "Cipher suite"),
                ("certificate_subject", "Certificate subject"),
                ("certificate_issuer", "Certificate issuer"),
                ("certificate_san", "Certificate subject alternative names"),
                ("certificate_not_before", "Certificate valid from"),
                ("certificate_not_after", "Certificate valid until"),
                ("certificate_sha256", "Certificate SHA-256 fingerprint"),
                ("verification_error", "Verification error"),
                ("verification_code", "Verification code"),
                ("verification_message", "Verification message"),
                ("error", "Additional probe error"),
            ):
                value = tls_info.get(key)
                if value:
                    tls_evidence.append(f"{label}: {value}")

            failure_details = classify_tls_verification_failure(tls_info)
            error_detail = (
                tls_info.get("verification_message")
                or tls_info.get("verification_error")
                or "詳細不明"
            )
            tls_severity = "INFO" if scope == "LOOPBACK" else "MEDIUM"
            if scope == "LOOPBACK":
                scope_explanation = (
                    "接続先はループバックアドレスです。この結果だけでは、別ホストや"
                    "外部ネットワークに同じ証明書エラーが露出しているとは判断できません。"
                )
            else:
                scope_explanation = scope_note

            findings.append({
                "type": "TLS",
                "subtype": failure_details["subtype"],
                "severity": tls_severity,
                "title": f"TCPポート {port}: {failure_details['title']}",
                "url": target_url,
                "description": (
                    f"{host}:{port} でTLS証明書の検証に失敗しました。検証情報: {error_detail}。"
                    f"{failure_details['description']} {scope_explanation}"
                ),
                "evidence": "\n".join(tls_evidence),
                "recommendation": failure_details["recommendation"],
            })

    if not findings:
        scope = classify_network_scope(host)
        scope_label, scope_note = _scope_context(scope)
        findings.append({
            "type": "PORT_SCAN",
            "subtype": "NO_CONFIGURED_PORT_DETECTED",
            "severity": "INFO",
            "title": "設定されたTCPポートへの接続を確認できませんでした",
            "url": target_url,
            "description": (
                "設定されたWeb・管理・データベース関連ポートへのTCP接続を試みましたが、"
                "接続できるポートは確認されませんでした。ファイアウォール、ネットワーク経路、"
                "またはサービスの待ち受け設定の影響も考えられます。 "
                f"{scope_note}"
            ),
            "evidence": (
                f"Host: {host}\n"
                f"Network scope: {scope} ({scope_label})\n"
                f"Checked ports: {', '.join(map(str, SERVICE_PORTS))}"
            ),
            "recommendation": (
                "必要なサービスが稼働している場合は、待ち受けポートとファイアウォール設定を確認してください。"
            ),
        })

    return findings
