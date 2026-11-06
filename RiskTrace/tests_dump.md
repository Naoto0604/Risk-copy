===== FILE: tests/https_test_server.py =====
"""RiskTrace用のローカルHTTPSテストサーバー（127.0.0.1:8443）。

実行:
    python tests/https_test_server.py
停止:
    Ctrl+C

cryptography パッケージが必要。証明書は実行時に自動生成され、
自己署名なのでブラウザや通常の証明書検証では信頼されない想定。
"""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
import ssl
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("cryptography が必要です。次を実行してください: python -m pip install cryptography")
    raise SystemExit(1)

HOST = "127.0.0.1"
PORT = 8443
CERT_DIR = Path(__file__).resolve().parent / ".tls_test_cert"
CERT_FILE = CERT_DIR / "localhost-cert.pem"
KEY_FILE = CERT_DIR / "localhost-key.pem"


def create_self_signed_certificate():
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RiskTrace Local Test"),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=2)).replace(tzinfo=None))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ip_address(HOST)),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    KEY_FILE.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    CERT_FILE.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_page(self, include_body=True):
        body = (
            b"<!doctype html><html><head><title>RiskTrace TLS Test</title>"
            b"</head><body><h1>Local HTTPS test server</h1></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        self._send_page(include_body=True)

    def do_HEAD(self):
        self._send_page(include_body=False)

    def log_message(self, fmt, *args):
        print("[HTTPS TEST] " + (fmt % args))


def main():
    create_self_signed_certificate()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"HTTPS test server running at https://{HOST}:{PORT}/")
    print("Self-signed certificate: TLS inspection should record verification FAILED.")
    print("Stop with Ctrl+C. Use only as a local test service.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping HTTPS test server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

===== FILE: tests/old_test_port_check.py =====
import unittest
from unittest.mock import MagicMock, patch
from scanner.old4_port_check import probe_http_service
from scanner.old4_port_check import check_web_ports

class TestPortCheck(unittest.TestCase):

    @patch("scanner.port_check.socket.create_connection")
    def test_open_port_is_reported(self, mock_connection):
        """接続できるポートをFindingとして報告する。"""

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 5000:
                return MagicMock()

            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect

        findings = check_web_ports("http://example.com")

        port_findings = [
            finding
            for finding in findings
            if finding.get("type") == "PORT_SCAN"
            and "5000" in finding.get("title", "")
        ]

        self.assertTrue(port_findings)
        self.assertEqual(port_findings[0]["severity"], "LOW")
        self.assertTrue(port_findings[0]["recommendation"])

    @patch("scanner.port_check.socket.create_connection")
    def test_no_open_ports_is_reported(self, mock_connection):
        """接続可能なポートがなければ、その旨を報告する。"""

        mock_connection.side_effect = OSError("Port is closed")

        findings = check_web_ports("http://example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "PORT_SCAN")
        self.assertEqual(
            findings[0]["subtype"],
            "NO_OPEN_WEB_PORT_DETECTED",
        )

    @patch("scanner.port_check.socket.create_connection")
    def test_http_server_header_is_detected(self, mock_connection):
        """HTTP応答からServerヘッダーを取得する。"""

        mock_socket = MagicMock()
        mock_socket.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Werkzeug/3.1.3\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        mock_connection.return_value = mock_socket

        status_line, server_header = probe_http_service(
            "127.0.0.1",
            5000,
        )

        self.assertEqual(status_line, "HTTP/1.1 200 OK")
        self.assertEqual(server_header, "Werkzeug/3.1.3")

    
    def test_invalid_url_is_rejected(self):
        """HTTP・HTTPS以外のURLを拒否する。"""

        with self.assertRaises(ValueError):
            check_web_ports("ftp://example.com")


    def test_tls_details_are_included(self):
        """TLS検査に成功した場合、情報をEvidenceへ含める。"""

        tls_result = {
            "verification": "PASSED",
            "verification_error": None,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256 (128 bits)",
            "certificate_subject": "CN=example.com",
            "certificate_issuer": "CN=Example CA",
            "certificate_not_before": "2026-01-01T00:00:00Z",
            "certificate_not_after": "2027-01-01T00:00:00Z",
            "certificate_san": "DNS:example.com",
            "certificate_sha256": "a" * 64,
            "error": None,
        }

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 443:
                return MagicMock()
            raise OSError("Port is closed")

        with patch(
            "scanner.port_check.socket.create_connection",
            side_effect=connection_side_effect,
        ), patch(
            "scanner.port_check.probe_tls_service",
            return_value=tls_result,
        ):
            findings = check_web_ports("https://example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "PORT_SCAN")
        self.assertIn("TLS version: TLSv1.3", findings[0]["evidence"])
        self.assertIn("Certificate SHA-256 fingerprint:", findings[0]["evidence"])

    def test_tls_verification_failure_creates_finding(self):
        """TLS証明書の検証失敗を独立したFindingとして記録する。"""

        tls_result = {
            "verification": "FAILED",
            "verification_error": "hostname mismatch",
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256 (128 bits)",
            "certificate_subject": "CN=wrong.example.com",
            "certificate_issuer": "CN=Example CA",
            "certificate_not_before": None,
            "certificate_not_after": None,
            "certificate_san": "DNS:wrong.example.com",
            "certificate_sha256": "b" * 64,
            "error": None,
        }

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 443:
                return MagicMock()
            raise OSError("Port is closed")

        with patch(
            "scanner.port_check.socket.create_connection",
            side_effect=connection_side_effect,
        ), patch(
            "scanner.port_check.probe_tls_service",
            return_value=tls_result,
        ):
            findings = check_web_ports("https://example.com")

        tls_findings = [
            finding
            for finding in findings
            if finding.get("type") == "TLS"
        ]

        self.assertEqual(len(tls_findings), 1)
        self.assertEqual(
            tls_findings[0]["subtype"],
            "TLS_HOSTNAME_MISMATCH",
        )
        self.assertEqual(tls_findings[0]["severity"], "MEDIUM")
        self.assertIn("hostname mismatch", tls_findings[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
===== FILE: tests/test_crawler.py =====
import unittest
from unittest.mock import patch

import requests

from scanner.crawler import crawl


def make_response(status_code=200, html="", location=None):
    response = requests.Response()
    response.status_code = status_code
    response._content = html.encode("utf-8")
    response.encoding = "utf-8"
    response.headers["Content-Type"] = "text/html; charset=utf-8"

    if location:
        response.headers["Location"] = location

    return response


class TestCrawler(unittest.TestCase):

    @patch("scanner.crawler.requests.get")
    def test_external_redirect_is_not_followed(self, mock_get):
        """外部ホストへのリダイレクトを自動追跡しない。"""
        mock_get.return_value = make_response(
            302,
            location="http://evil.example/",
        )

        result = crawl("http://example.com/", max_pages=10)

        self.assertEqual(result, set())
        mock_get.assert_called_once_with(
            "http://example.com/",
            timeout=5,
            allow_redirects=False,
        )

    @patch("scanner.crawler.requests.get")
    def test_external_link_is_not_crawled(self, mock_get):
        """ページ内の外部リンクを巡回しない。"""
        mock_get.side_effect = [
            make_response(
                html=(
                    '<a href="/inside">内部</a>'
                    '<a href="http://evil.example/">外部</a>'
                )
            ),
            make_response(html="<p>内部ページ</p>"),
        ]

        result = crawl("http://example.com/", max_pages=10)

        self.assertEqual(
            result,
            {
                "http://example.com/",
                "http://example.com/inside",
            },
        )
        self.assertEqual(mock_get.call_count, 2)

    @patch("scanner.crawler.requests.get")
    def test_same_host_port_is_required(self, mock_get):
        """別ポートへのリンクを巡回しない。"""
        mock_get.return_value = make_response(
            html='<a href="http://example.com:8000/">別ポート</a>'
        )

        result = crawl("http://example.com/", max_pages=10)

        self.assertEqual(result, {"http://example.com/"})
        mock_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
===== FILE: tests/test_port_check.py =====
import unittest
from unittest.mock import MagicMock, patch
from scanner.port_check import probe_http_service, check_web_ports, SERVICE_PORTS


class TestPortCheck(unittest.TestCase):

    @patch("scanner.port_check.socket.create_connection")
    def test_open_port_is_reported(self, mock_connection):
        """接続できるポートをFindingとして報告する。"""

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 5000:
                return MagicMock()

            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect

        findings = check_web_ports("http://example.com")

        port_findings = [
            finding
            for finding in findings
            if finding.get("type") == "PORT_SCAN"
            and "5000" in finding.get("title", "")
        ]

        self.assertTrue(port_findings)
        self.assertEqual(port_findings[0]["severity"], "LOW")
        self.assertTrue(port_findings[0]["recommendation"])

    @patch("scanner.port_check.socket.create_connection")
    def test_no_open_ports_is_reported(self, mock_connection):
        """接続可能なポートがなければ、その旨を報告する。"""

        mock_connection.side_effect = OSError("Port is closed")

        findings = check_web_ports("http://example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "PORT_SCAN")
        self.assertEqual(
            findings[0]["subtype"],
            "NO_CONFIGURED_PORT_DETECTED",
        )

    @patch("scanner.port_check.socket.create_connection")
    def test_http_server_header_is_detected(self, mock_connection):
        """HTTP応答からServerヘッダーを取得する。"""

        mock_socket = MagicMock()
        mock_socket.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Werkzeug/3.1.3\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        mock_connection.return_value = mock_socket

        status_line, server_header = probe_http_service(
            "127.0.0.1",
            5000,
        )

        self.assertEqual(status_line, "HTTP/1.1 200 OK")
        self.assertEqual(server_header, "Werkzeug/3.1.3")

    
    def test_invalid_url_is_rejected(self):
        """HTTP・HTTPS以外のURLを拒否する。"""

        with self.assertRaises(ValueError):
            check_web_ports("ftp://example.com")


    def test_tls_details_are_included(self):
        """TLS検査に成功した場合、情報をEvidenceへ含める。"""

        tls_result = {
            "verification": "PASSED",
            "verification_error": None,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256 (128 bits)",
            "certificate_subject": "CN=example.com",
            "certificate_issuer": "CN=Example CA",
            "certificate_not_before": "2026-01-01T00:00:00Z",
            "certificate_not_after": "2027-01-01T00:00:00Z",
            "certificate_san": "DNS:example.com",
            "certificate_sha256": "a" * 64,
            "error": None,
        }

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 443:
                return MagicMock()
            raise OSError("Port is closed")

        with patch(
            "scanner.port_check.socket.create_connection",
            side_effect=connection_side_effect,
        ), patch(
            "scanner.port_check.probe_tls_service",
            return_value=tls_result,
        ):
            findings = check_web_ports("https://example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "PORT_SCAN")
        self.assertIn("TLS version: TLSv1.3", findings[0]["evidence"])
        self.assertIn("Certificate SHA-256 fingerprint:", findings[0]["evidence"])

    def test_tls_verification_failure_creates_finding(self):
        """TLS証明書の検証失敗を独立したFindingとして記録する。"""

        tls_result = {
            "verification": "FAILED",
            "verification_error": "hostname mismatch",
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256 (128 bits)",
            "certificate_subject": "CN=wrong.example.com",
            "certificate_issuer": "CN=Example CA",
            "certificate_not_before": None,
            "certificate_not_after": None,
            "certificate_san": "DNS:wrong.example.com",
            "certificate_sha256": "b" * 64,
            "error": None,
        }

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 443:
                return MagicMock()
            raise OSError("Port is closed")

        with patch(
            "scanner.port_check.socket.create_connection",
            side_effect=connection_side_effect,
        ), patch(
            "scanner.port_check.probe_tls_service",
            return_value=tls_result,
        ):
            findings = check_web_ports("https://example.com")

        tls_findings = [
            finding
            for finding in findings
            if finding.get("type") == "TLS"
        ]

        self.assertEqual(len(tls_findings), 1)
        self.assertEqual(
            tls_findings[0]["subtype"],
            "TLS_HOSTNAME_MISMATCH",
        )
        self.assertEqual(tls_findings[0]["severity"], "MEDIUM")
        self.assertIn("hostname mismatch", tls_findings[0]["evidence"])


    @patch("scanner.port_check.probe_service_banner", return_value=None)
    @patch("scanner.port_check.socket.create_connection")
    def test_database_port_is_reported_for_review(self, mock_connection, mock_service_probe):
        """MySQLポートの接続を、脆弱性と断定せず要確認として報告する。"""

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 3306:
                return MagicMock()
            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect

        findings = check_web_ports("http://example.com")
        database_findings = [
            finding for finding in findings
            if finding.get("type") == "PORT_SCAN"
            and "3306" in finding.get("title", "")
        ]

        self.assertEqual(len(database_findings), 1)
        self.assertEqual(database_findings[0]["severity"], "LOW")
        self.assertIn("MySQL", database_findings[0]["title"])
        self.assertIn("実際のサービス", database_findings[0]["description"])
        self.assertTrue(database_findings[0]["recommendation"])

    @patch("scanner.port_check.probe_service_banner", return_value=None)
    @patch("scanner.port_check.probe_http_service")
    @patch("scanner.port_check.socket.create_connection")
    def test_non_http_services_are_not_sent_http_requests(
        self, mock_connection, mock_http_probe, mock_service_probe
    ):
        """管理・DBポートにHTTP HEADリクエストを送らない。"""

        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 3306:
                return MagicMock()
            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect
        findings = check_web_ports("http://example.com")

        self.assertTrue(any("3306" in f.get("title", "") for f in findings))
        mock_http_probe.assert_not_called()

    def test_common_service_ports_are_configured(self):
        """主要な管理・データベースポートが固定リストに含まれる。"""
        for port in (21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017):
            with self.subTest(port=port):
                self.assertIn(port, SERVICE_PORTS)


    @staticmethod
    def _connected_socket(peer_ip, port):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.getpeername.return_value = (peer_ip, port)
        return connection

    @patch("scanner.port_check.socket.create_connection")
    def test_loopback_sensitive_port_is_contextualized(self, mock_connection):
        """ループバックのサービス検出を外部公開と誤認しない。"""
        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 445:
                return self._connected_socket("127.0.0.1", 445)
            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect
        findings = check_web_ports("http://127.0.0.1:5000")
        port_finding = next(
            f for f in findings
            if f.get("type") == "PORT_SCAN" and "445" in f.get("title", "")
        )

        self.assertEqual(port_finding["severity"], "INFO")
        self.assertIn("Network scope: LOOPBACK", port_finding["evidence"])
        self.assertIn("TCP_CONNECTION_ONLY", port_finding["evidence"])
        self.assertIn("外部ネットワーク", port_finding["description"])
        self.assertIn("実際のサービス", port_finding["description"])

    @patch("scanner.port_check.probe_service_banner", return_value=None)
    @patch("scanner.port_check.socket.create_connection")
    def test_private_address_sensitive_port_is_low_review(self, mock_connection, mock_service_probe):
        """プライベートIPの接続を確認し、インターネット公開とは断定しない。"""
        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 3306:
                return self._connected_socket("192.168.1.20", 3306)
            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect
        findings = check_web_ports("http://db.internal")
        port_finding = next(
            f for f in findings
            if f.get("type") == "PORT_SCAN" and "3306" in f.get("title", "")
        )

        self.assertEqual(port_finding["severity"], "LOW")
        self.assertIn("Network scope: PRIVATE", port_finding["evidence"])
        self.assertIn("インターネットからの到達可能性", port_finding["description"])

    @patch("scanner.port_check.probe_service_banner", return_value=None)
    @patch("scanner.port_check.socket.create_connection")
    def test_global_address_does_not_claim_internet_wide_exposure(self, mock_connection, mock_service_probe):
        """グローバルIPへの到達を、全インターネットからの到達性と混同しない。"""
        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 3306:
                return self._connected_socket("8.8.8.8", 3306)
            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect
        findings = check_web_ports("http://example.com")
        port_finding = next(
            f for f in findings
            if f.get("type") == "PORT_SCAN" and "3306" in f.get("title", "")
        )

        self.assertEqual(port_finding["severity"], "LOW")
        self.assertIn("Network scope: PUBLIC", port_finding["evidence"])
        self.assertIn("インターネット上の全地点", port_finding["description"])

    @patch("scanner.port_check.probe_service_banner", return_value=None)
    @patch("scanner.port_check.socket.create_connection")
    def test_service_confidence_is_explicit_for_tcp_only_ports(self, mock_connection, mock_service_probe):
        """非HTTPサービスはTCP接続のみで、サービス特定とは表示しない。"""
        def connection_side_effect(address, timeout=None, **kwargs):
            if address[1] == 3306:
                return self._connected_socket("192.168.1.20", 3306)
            raise OSError("Port is closed")

        mock_connection.side_effect = connection_side_effect
        findings = check_web_ports("http://db.internal")
        port_finding = next(
            f for f in findings
            if f.get("type") == "PORT_SCAN" and "3306" in f.get("title", "")
        )

        self.assertIn("TCP_CONNECTION_ONLY", port_finding["evidence"])
        self.assertIn("実際のサービスは未確認", port_finding["evidence"])
        self.assertIn("Expected service (port-based guess)", port_finding["evidence"])



if __name__ == "__main__":
    unittest.main()
===== FILE: tests/test_report_export.py =====
import csv
import io
import json
import unittest

from report_export import (
    build_csv_bytes,
    build_export_payload,
    build_json_bytes,
    register_export_routes,
)

try:
    from flask import Flask
except ImportError:  # Helper tests can still run without Flask installed.
    Flask = None


SAMPLE_SCAN = {
    "id": "scan-123",
    "target_url": "https://example.test/",
    "protocol": "https",
    "status": "COMPLETED",
    "created_at": "2026-10-27 12:00:00",
    "analysis_options": '["score", "priority"]',
    "checks_options": '["https", "ports"]',
}

SAMPLE_FINDINGS = [
    {
        "id": 10,
        "scan_id": "scan-123",
        "type": "TLS",
        "subtype": "TLS_CERTIFICATE_VERIFICATION_FAILED",
        "severity": "MEDIUM",
        "title": "証明書の検証に失敗しました",
        "url": "https://example.test/",
        "description": "自己署名証明書です",
        "evidence": "TLS certificate verification: FAILED",
        "recommendation": "証明書チェーンを確認してください",
    }
]


class TestReportExportHelpers(unittest.TestCase):
    def test_json_export_preserves_japanese_and_options(self):
        content = build_json_bytes(SAMPLE_SCAN, SAMPLE_FINDINGS)
        payload = json.loads(content.decode("utf-8"))

        self.assertEqual(payload["scan"]["analysis_options"], ["score", "priority"])
        self.assertEqual(payload["summary"]["finding_count"], 1)
        self.assertEqual(payload["summary"]["severity_counts"]["MEDIUM"], 1)
        self.assertIn("証明書", payload["findings"][0]["title"])

    def test_json_export_contains_schema_version(self):
        payload = build_export_payload(SAMPLE_SCAN, SAMPLE_FINDINGS, exported_at="2026-10-27T00:00:00+00:00")
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["exported_at"], "2026-10-27T00:00:00+00:00")

    def test_csv_export_has_one_row_per_finding(self):
        content = build_csv_bytes(SAMPLE_SCAN, SAMPLE_FINDINGS).decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(content, newline="")))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "MEDIUM")
        self.assertEqual(rows[0]["target_url"], SAMPLE_SCAN["target_url"])
        self.assertIn("証明書", rows[0]["title"])

    def test_csv_export_mitigates_formula_injection(self):
        findings = [dict(SAMPLE_FINDINGS[0], title="=HYPERLINK(\"https://bad.example\")")]
        content = build_csv_bytes(SAMPLE_SCAN, findings).decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(content, newline="")))
        self.assertTrue(rows[0]["title"].startswith("'="))

    def test_csv_export_is_excel_friendly_utf8_with_bom(self):
        content = build_csv_bytes(SAMPLE_SCAN, SAMPLE_FINDINGS)
        self.assertTrue(content.startswith(b"\xef\xbb\xbf"))

    def test_missing_scan_is_rejected_by_payload_builder(self):
        with self.assertRaises(ValueError):
            build_export_payload(None, [])

    def test_empty_findings_still_exports_header(self):
        content = build_csv_bytes(SAMPLE_SCAN, []).decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(content, newline="")))
        self.assertEqual(len(rows), 1)
        self.assertIn("finding_id", rows[0])


@unittest.skipIf(Flask is None, "Flask is required for route integration tests")
class TestReportExportRoutes(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        register_export_routes(
            self.app,
            get_scan=lambda scan_id: SAMPLE_SCAN if scan_id == "scan-123" else None,
            get_findings=lambda scan_id: SAMPLE_FINDINGS,
        )
        self.client = self.app.test_client()

    def test_json_route_downloads_completed_scan(self):
        response = self.client.get("/export/scan-123/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.content_type)
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertEqual(json.loads(response.data)["summary"]["finding_count"], 1)

    def test_csv_route_downloads_completed_scan(self):
        response = self.client.get("/export/scan-123/csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn(".csv", response.headers["Content-Disposition"])

    def test_unknown_scan_returns_404(self):
        response = self.client.get("/export/unknown/json")
        self.assertEqual(response.status_code, 404)

    def test_unsupported_format_returns_404(self):
        response = self.client.get("/export/scan-123/xml")
        self.assertEqual(response.status_code, 404)

    def test_incomplete_scan_returns_409(self):
        app = Flask("incomplete-test")
        app.config["TESTING"] = True
        incomplete = dict(SAMPLE_SCAN, status="RUNNING")
        register_export_routes(
            app,
            get_scan=lambda scan_id: incomplete,
            get_findings=lambda scan_id: [],
        )
        response = app.test_client().get("/export/scan-123/json")
        self.assertEqual(response.status_code, 409)


if __name__ == "__main__":
    unittest.main()

===== FILE: tests/test_safe_request.py =====
import unittest
from unittest.mock import patch, MagicMock
import requests
from app import safe_request, MAX_REDIRECTS

def make_response(status_code, location=None):
    """テスト用のHTTPレスポンスを作る。"""
    response = requests.Response()
    response.status_code = status_code
    response._content = b"Test response"
    response.headers = {}
    response.raw = MagicMock()

    if location is not None:
        response.headers["Location"] = location

    return response

class TestSafeRequest(unittest.TestCase):

    @patch("app.requests.get")
    def test_normal_response(self, mock_get):
        """通常のページはそのまま返す。"""
        expected = make_response(200)
        mock_get.return_value = expected

        result = safe_request("https://example.com/")

        self.assertIs(result, expected)
        mock_get.assert_called_once()

    @patch("app.requests.get")
    def test_same_host_redirect(self, mock_get):
        """同じホストへのリダイレクトは追跡する。"""
        redirect = make_response(302, "/next")
        final_response = make_response(200)
        mock_get.side_effect = [redirect, final_response]

        result = safe_request("https://example.com/start")

        self.assertIs(result, final_response)
        self.assertEqual(len(result.history), 1)
        self.assertEqual(mock_get.call_count, 2)

    @patch("app.requests.get")
    def test_external_host_is_rejected(self, mock_get):
        """外部ホストへのリダイレクトは拒否する。"""
        mock_get.return_value = make_response(
            302, "https://other.example/"
        )

        with self.assertRaises(requests.RequestException):
            safe_request("https://example.com/")

        # 外部ホストにはリクエストしていない
        mock_get.assert_called_once()

    @patch("app.requests.get")
    def test_redirect_limit(self, mock_get):
        """リダイレクト回数の上限で停止する。"""
        mock_get.side_effect = [
            make_response(302, "/loop")
            for _ in range(MAX_REDIRECTS + 1)
        ]

        with self.assertRaises(requests.TooManyRedirects):
            safe_request("https://example.com/loop")

        self.assertEqual(
            mock_get.call_count,
            MAX_REDIRECTS + 1,
        )


if __name__ == "__main__":
    unittest.main()

===== FILE: tests/test_service_probe.py =====
import unittest
from unittest.mock import MagicMock, patch

from scanner.port_check import probe_service_banner, check_web_ports


class FakeSocket:
    """プロトコル応答を返す、ネットワークを使わないテスト用ソケット。"""

    def __init__(self, recv_chunks=()):
        self.recv_chunks = list(recv_chunks)
        self.sent = []
        self.timeout = None
        self.peer = ("192.0.2.10", 0)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        if not self.recv_chunks:
            return b""
        chunk = self.recv_chunks.pop(0)
        if len(chunk) <= size:
            return chunk
        self.recv_chunks.insert(0, chunk[size:])
        return chunk[:size]

    def sendall(self, data):
        self.sent.append(data)

    def getpeername(self):
        return self.peer


class TestServiceProbe(unittest.TestCase):

    @patch("scanner.port_check.socket.create_connection")
    def test_ssh_banner_is_observed(self, mock_connect):
        mock_connect.return_value = FakeSocket([b"SSH-2.0-OpenSSH_9.6\r\n"])

        result = probe_service_banner("example.test", 22)

        self.assertIsNotNone(result)
        self.assertEqual(result["code"], "SSH_BANNER_OBSERVED")
        self.assertIn("OpenSSH_9.6", result["evidence"])
        self.assertIn("未検証", result["label"])

    @patch("scanner.port_check.socket.create_connection")
    def test_ftp_greeting_is_observed_without_sending_commands(self, mock_connect):
        fake_socket = FakeSocket([b"220 FTP service ready\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 21)

        self.assertEqual(result["code"], "FTP_GREETING_OBSERVED")
        self.assertIn("220 FTP service ready", result["evidence"])
        self.assertEqual(fake_socket.sent, [])

    @patch("scanner.port_check.socket.create_connection")
    def test_smtp_greeting_is_observed_without_authentication(self, mock_connect):
        fake_socket = FakeSocket([b"220 mail.example.test ESMTP ready\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 587)

        self.assertEqual(result["code"], "SMTP_GREETING_OBSERVED")
        self.assertIn("SMTP Submission", result["protocol"])
        self.assertEqual(fake_socket.sent, [])

    @patch("scanner.port_check.socket.create_connection")
    def test_mysql_initial_handshake_version_is_observed(self, mock_connect):
        payload = b"\x0a8.0.36-risktrace\x00"
        header = len(payload).to_bytes(3, "little") + b"\x00"
        fake_socket = FakeSocket([header, payload])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 3306)

        self.assertIsNotNone(result)
        self.assertEqual(result["code"], "MYSQL_HANDSHAKE_OBSERVED")
        self.assertIn("8.0.36-risktrace", result["evidence"])
        self.assertEqual(fake_socket.sent, [])  # no login/auth packet was sent

    @patch("scanner.port_check.socket.create_connection")
    def test_redis_ping_is_read_only_and_pong_is_observed(self, mock_connect):
        fake_socket = FakeSocket([b"+PONG\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 6379)

        self.assertEqual(result["code"], "REDIS_PING_RESPONSE_OBSERVED")
        self.assertEqual(fake_socket.sent, [b"*1\r\n$4\r\nPING\r\n"])
        self.assertIn("読み取り専用", result["note"])

    @patch("scanner.port_check.socket.create_connection")
    def test_redis_noauth_response_is_observed_without_credentials(self, mock_connect):
        fake_socket = FakeSocket([b"-NOAUTH Authentication required.\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 6379)

        self.assertEqual(result["code"], "REDIS_AUTH_REQUIRED_RESPONSE_OBSERVED")
        self.assertEqual(fake_socket.sent, [b"*1\r\n$4\r\nPING\r\n"])

    @patch("scanner.port_check.socket.create_connection")
    def test_protocol_probe_is_added_to_port_finding(self, mock_connect):
        """プロトコル応答がサービスのFindingにEvidenceとして保存される。"""
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.getpeername.return_value = ("127.0.0.1", 22)

        def connect_side_effect(address, timeout=None, **kwargs):
            if address[1] == 22:
                return connection
            raise OSError("closed")

        mock_connect.side_effect = connect_side_effect
        probe_result = {
            "protocol": "SSH",
            "code": "SSH_BANNER_OBSERVED",
            "label": "SSH識別バナーを観測。製品・バージョン情報は未検証。",
            "note": "バナーは偽装可能です。",
            "evidence": "Observed SSH banner (unverified): SSH-2.0-TestSSH",
            "observed_value": "SSH-2.0-TestSSH",
        }

        with patch(
            "scanner.port_check.probe_service_banner",
            return_value=probe_result,
        ):
            findings = check_web_ports("http://127.0.0.1:5000")

        ssh_finding = next(
            finding for finding in findings
            if finding.get("type") == "PORT_SCAN" and "22" in finding.get("title", "")
        )
        self.assertIn("SSH_BANNER_OBSERVED", ssh_finding["evidence"])
        self.assertIn("SSH-2.0-TestSSH", ssh_finding["evidence"])
        self.assertIn("偽装可能", ssh_finding["evidence"])

    def test_unsupported_port_is_not_probed(self):
        self.assertIsNone(probe_service_banner("example.test", 445))


if __name__ == "__main__":
    unittest.main()

===== FILE: tests/test_vulnerability_lookup.py =====
import unittest
from unittest.mock import patch


from analyzer.vulnerability_lookup import (
    extract_observed_products,
    lookup_cve_candidates,
)


class TestVulnerabilityLookup(unittest.TestCase):
    def mysql_finding(self, evidence=None):
        return {
            "type": "PORT_SCAN",
            "subtype": "TCP_PORT_OPEN",
            "severity": "INFO",
            "title": "MySQL port observed",
            "url": "http://127.0.0.1:5000/",
            "description": "TCP connection observed.",
            "evidence": evidence or (
                "Host: 127.0.0.1\n"
                "Port: 3306\n"
                "Service identification: MYSQL_HANDSHAKE_OBSERVED\n"
                "Observed MySQL server version string (unverified): 8.0.25"
            ),
        }

    def test_extracts_mysql_cpe_from_unverified_banner(self):
        products = extract_observed_products([self.mysql_finding()])
        self.assertEqual(len(products), 1)
        self.assertEqual(products[0]["name"], "MySQL Server")
        self.assertEqual(products[0]["version"], "8.0.25")
        self.assertEqual(
            products[0]["cpe"],
            "cpe:2.3:a:oracle:mysql:8.0.25:*:*:*:*:*:*:*",
        )

    def test_ignores_port_only_observation_without_version(self):
        finding = self.mysql_finding("Host: 127.0.0.1\nPort: 3306\nTCP_CONNECTION_ONLY")
        self.assertEqual(extract_observed_products([finding]), [])

    def test_creates_informational_candidate_for_nvd_cve(self):
        nvd_data = {
            "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?example",
            "total_results": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-12345",
                    "vulnStatus": "Analyzed",
                    "published": "2024-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Example issue."}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        }]
                    },
                }
            }],
        }
        with patch("analyzer.vulnerability_lookup._fetch_nvd_by_cpe", return_value=nvd_data):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["type"], "VULNERABILITY_LOOKUP")
        self.assertEqual(generated[0]["subtype"], "CVE_VERSION_CANDIDATE")
        self.assertEqual(generated[0]["severity"], "INFO")
        self.assertIn("CVE-2024-12345", generated[0]["title"])
        self.assertIn("未検証", generated[0]["description"])
        self.assertIn("NVD CVSS base score: 7.5", generated[0]["evidence"])

    def test_no_matching_cves_is_not_claimed_as_no_vulnerabilities(self):
        empty_data = {
            "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?example",
            "total_results": 0,
            "vulnerabilities": [],
        }
        with patch("analyzer.vulnerability_lookup._fetch_nvd_by_cpe", return_value=empty_data):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["subtype"], "NO_CVE_MATCH_FOUND")
        self.assertIn("脆弱性が存在しないことの証明にはなりません", generated[0]["recommendation"])

    def test_nvd_outage_does_not_fail_lookup(self):
        with patch(
            "analyzer.vulnerability_lookup._fetch_nvd_by_cpe",
            side_effect=RuntimeError("NVD API HTTP 503"),
        ):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["subtype"], "NVD_LOOKUP_UNAVAILABLE")
        self.assertEqual(generated[0]["severity"], "INFO")

    def test_rejected_cves_are_ignored(self):
        nvd_data = {
            "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?example",
            "total_results": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-12345",
                    "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "Rejected record."}],
                }
            }],
        }
        with patch("analyzer.vulnerability_lookup._fetch_nvd_by_cpe", return_value=nvd_data):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["subtype"], "NO_CVE_MATCH_FOUND")

    def test_open_ssh_banner_is_supported(self):
        finding = {
            "type": "PORT_SCAN",
            "url": "http://example.test/",
            "evidence": "Observed SSH banner (unverified): SSH-2.0-OpenSSH_9.6p1",
        }
        products = extract_observed_products([finding])
        self.assertEqual(len(products), 1)
        self.assertEqual(products[0]["name"], "OpenSSH")
        self.assertEqual(products[0]["version"], "9.6p1")

    def test_http_server_banner_supports_apache(self):
        finding = {
            "type": "PORT_SCAN",
            "url": "https://example.test/",
            "evidence": "Server header (unverified banner): Apache/2.4.58",
        }
        products = extract_observed_products([finding])
        self.assertEqual(len(products), 1)
        self.assertEqual(products[0]["name"], "Apache HTTP Server")
        self.assertEqual(products[0]["version"], "2.4.58")

    def test_duplicate_product_version_is_queried_once(self):
        findings = [self.mysql_finding(), self.mysql_finding()]
        products = extract_observed_products(findings)
        self.assertEqual(len(products), 1)


    def _server_cve(self, cve_id, description, *, criteria="cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", **range_fields):
        cpe_match = {
            "vulnerable": True,
            "criteria": criteria,
            **range_fields,
        }
        return {
            "cve": {
                "id": cve_id,
                "vulnStatus": "Analyzed",
                "published": "2021-10-20T00:00:00.000",
                "descriptions": [{"lang": "en", "value": description}],
                "configurations": [{
                    "operator": "OR",
                    "nodes": [{"operator": "OR", "cpeMatch": [cpe_match]}],
                }],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 7.1,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H",
                        }
                    }]
                },
            }
        }

    def _nvd_response(self, *cves):
        return {
            "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?example",
            "total_results": len(cves),
            "vulnerabilities": list(cves),
        }

    def test_filters_mysql_client_cve_when_observed_product_is_server(self):
        """MySQL Client/C API CVEs are not presented as MySQL Server CVEs."""
        client_cve = self._server_cve(
            "CVE-2021-35597",
            "Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are affected are 8.0.26 and prior.",
            versionEndIncluding="8.0.26",
        )
        with patch(
            "analyzer.vulnerability_lookup._fetch_nvd_by_cpe",
            return_value=self._nvd_response(client_cve),
        ):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["subtype"], "CANDIDATES_EXCLUDED_BY_COMPONENT")
        self.assertNotIn("CVE-2021-35597", generated[0]["title"])
        self.assertIn("MySQL Client/C API", generated[0]["evidence"])

    def test_version_outside_nvd_range_is_filtered(self):
        """A version newer than versionEndIncluding is not reported as a candidate."""
        finding = self.mysql_finding(
            "Host: 127.0.0.1\nPort: 3306\n"
            "Service identification: MYSQL_HANDSHAKE_OBSERVED\n"
            "Observed MySQL server version string (unverified): 8.0.27"
        )
        cve = self._server_cve(
            "CVE-2024-12345",
            "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).",
            versionEndIncluding="8.0.26",
        )
        with patch(
            "analyzer.vulnerability_lookup._fetch_nvd_by_cpe",
            return_value=self._nvd_response(cve),
        ):
            generated = lookup_cve_candidates([finding])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["subtype"], "CANDIDATES_OUTSIDE_AFFECTED_VERSION_RANGE")
        self.assertIn("8.0.27", generated[0]["evidence"])
        self.assertIn("versionEndIncluding=8.0.26", generated[0]["evidence"])

    def test_matching_server_cve_includes_cpe_range_assessment(self):
        """A matching product/version range remains a triage candidate with evidence."""
        cve = self._server_cve(
            "CVE-2024-12345",
            "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).",
            versionEndIncluding="8.0.26",
        )
        with patch(
            "analyzer.vulnerability_lookup._fetch_nvd_by_cpe",
            return_value=self._nvd_response(cve),
        ):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["subtype"], "CVE_VERSION_CANDIDATE")
        self.assertIn("CPE applicability status: MATCH", generated[0]["evidence"])
        self.assertIn("versionEndIncluding=8.0.26", generated[0]["evidence"])
        self.assertEqual(generated[0]["severity"], "INFO")

    def test_wrong_cpe_product_is_filtered(self):
        """A CPE for another product must not be accepted as a MySQL Server match."""
        cve = self._server_cve(
            "CVE-2024-12345",
            "Example component issue.",
            criteria="cpe:2.3:a:oracle:mysql_connector_c:*:*:*:*:*:*:*:*",
            versionEndIncluding="8.0.26",
        )
        with patch(
            "analyzer.vulnerability_lookup._fetch_nvd_by_cpe",
            return_value=self._nvd_response(cve),
        ):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["subtype"], "CANDIDATES_FILTERED_BY_CPE_APPLICABILITY")
        self.assertIn("oracle:mysql", generated[0]["evidence"])

    def test_exclusive_version_end_is_honored(self):
        """versionEndExcluding must reject the boundary version itself."""
        cve = self._server_cve(
            "CVE-2024-12345",
            "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).",
            versionEndExcluding="8.0.25",
        )
        with patch(
            "analyzer.vulnerability_lookup._fetch_nvd_by_cpe",
            return_value=self._nvd_response(cve),
        ):
            generated = lookup_cve_candidates([self.mysql_finding()])

        self.assertEqual(generated[0]["subtype"], "CANDIDATES_OUTSIDE_AFFECTED_VERSION_RANGE")
        self.assertIn("versionEndExcluding=8.0.25", generated[0]["evidence"])


if __name__ == "__main__":
    unittest.main()

