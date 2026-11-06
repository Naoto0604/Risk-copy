import hashlib
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
    80: "HTTP",
    443: "HTTPS",
    445: "SMB（ファイル共有）",
    1433: "Microsoft SQL Server",
    3000: "開発用Webサーバー",
    3306: "MySQL",
    3389: "RDP（リモートデスクトップ）",
    5000: "開発用Webサーバー",
    5432: "PostgreSQL",
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
    21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017
}

SERVICE_RECOMMENDATIONS = {
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


def check_web_ports(target_url, timeout=0.5):
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
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append((port, service))
        except OSError:
            continue

    findings = []

    for port, service in open_ports:
        is_development_port = port in DEVELOPMENT_PORTS
        tls_info = None

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
        else:
            # SSH/FTP/DB/SMB等のポートにHTTPデータを送らない。
            status_line, server_header = None, None

        if port in SENSITIVE_SERVICE_PORTS:
            severity = "LOW"
            title = f"{service}に使われることがあるTCPポート {port} への接続を確認しました（要確認）"
            description = (
                f"{host} のTCPポート {port} への接続を確認しました。"
                f"このポートは通常 {service} に使われますが、"
                "TCP接続だけでは実際のサービスやその設定は確認できません。"
                "開いていること自体で脆弱性と断定せず、必要性と接続元制限を確認してください。"
            )
            recommendation = SERVICE_RECOMMENDATIONS[port]
        elif is_development_port:
            severity = "LOW"
            title = (
                f"開発用Webサーバーに使われることがある"
                f"TCPポート {port} を確認しました"
            )
            description = (
                f"{host} のTCPポート {port} に接続できました。"
                "このポートは開発用サーバーで使われることがあります。"
                "ポート番号だけでは実際のサービスや脆弱性は確定できません。"
                "公開の必要性と接続制限を確認してください。"
            )
            recommendation = (
                "実際に稼働しているサービスを確認してください。"
                "開発用サーバーの場合は、不要な外部公開を避け、"
                "必要に応じて停止またはファイアウォールで接続元を制限してください。"
            )
        else:
            severity = "INFO"
            title = f"TCPポート {port} への接続を確認しました"
            description = (
                f"{host} のTCPポート {port} に接続できました。"
                f"想定用途は {service} です。"
                "ポートが開いていること自体は脆弱性を意味しません。"
                "実際のサービスと公開の必要性を確認してください。"
            )
            recommendation = (
                "待ち受けているサービスと公開の必要性を確認してください。"
                "不要なサービスは停止し、必要に応じて接続元を制限してください。"
            )

        evidence_lines = [
            f"Host: {host}",
            f"Port: {port}",
            f"Expected service: {service}",
            "Method: TCP connection",
        ]
        if status_line:
            evidence_lines.append(f"HTTP status: {status_line}")
        if server_header:
            evidence_lines.append(f"Server header: {server_header}")

        if tls_info is not None:
            evidence_lines.append(
                f"TLS certificate verification: {tls_info['verification']}"
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

        # 証明書検証失敗はポート検出とは別のFindingとして記録する。
        if tls_info and tls_info["verification"] == "FAILED":
            tls_evidence = [
                f"Host: {host}",
                f"Port: {port}",
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
            findings.append({
                "type": "TLS",
                "subtype": failure_details["subtype"],
                "severity": "MEDIUM",
                "title": f"TCPポート {port}: {failure_details['title']}",
                "url": target_url,
                "description": (
                    f"{host}:{port} でTLS証明書の検証に失敗しました。"
                    f"検証情報: {error_detail}。"
                    f"{failure_details['description']}"
                ),
                "evidence": "\n".join(tls_evidence),
                "recommendation": failure_details["recommendation"],
            })

    if not findings:
        findings.append({
            "type": "PORT_SCAN",
            "subtype": "NO_CONFIGURED_PORT_DETECTED",
            "severity": "INFO",
            "title": "設定されたTCPポートへの接続を確認できませんでした",
            "url": target_url,
            "description": (
                "設定されたWeb・管理・データベース関連ポートへのTCP接続を試みましたが、"
                "接続できるポートは確認されませんでした。"
                "ファイアウォール、ネットワーク経路、またはサービスの待ち受け設定の影響も考えられます。"
            ),
            "evidence": (
                f"Host: {host}\n"
                f"Checked ports: {', '.join(map(str, SERVICE_PORTS))}"
            ),
            "recommendation": (
                "必要なサービスが稼働している場合は、"
                "待ち受けポートとファイアウォール設定を確認してください。"
            ),
        })

    return findings
