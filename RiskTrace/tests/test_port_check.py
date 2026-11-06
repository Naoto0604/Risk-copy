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