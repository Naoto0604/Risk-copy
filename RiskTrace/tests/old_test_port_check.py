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