import unittest
from unittest.mock import MagicMock, patch

from engine.legacy_ports import check_web_ports, probe_service_banner
from engine.observations import Observation

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

    @patch("engine.legacy_ports.socket.create_connection")
    def test_ssh_banner_is_observed(self, mock_connect):
        mock_connect.return_value = FakeSocket([b"SSH-2.0-OpenSSH_9.6\r\n"])

        result = probe_service_banner("example.test", 22)

        self.assertIsNotNone(result)
        self.assertEqual(result["code"], "SSH_BANNER_OBSERVED")
        self.assertIn("OpenSSH_9.6", result["evidence"])
        self.assertIn("未検証", result["label"])

    @patch("engine.legacy_ports.socket.create_connection")
    def test_ftp_greeting_is_observed_without_sending_commands(self, mock_connect):
        fake_socket = FakeSocket([b"220 FTP service ready\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 21)

        self.assertEqual(result["code"], "FTP_GREETING_OBSERVED")
        self.assertIn("220 FTP service ready", result["evidence"])
        self.assertEqual(fake_socket.sent, [])

    @patch("engine.legacy_ports.socket.create_connection")
    def test_smtp_greeting_is_observed_without_authentication(self, mock_connect):
        fake_socket = FakeSocket([b"220 mail.example.test ESMTP ready\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 587)

        self.assertEqual(result["code"], "SMTP_GREETING_OBSERVED")
        self.assertIn("SMTP Submission", result["protocol"])
        self.assertEqual(fake_socket.sent, [])

    @patch("engine.legacy_ports.socket.create_connection")
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

    @patch("engine.legacy_ports.socket.create_connection")
    def test_redis_ping_is_read_only_and_pong_is_observed(self, mock_connect):
        fake_socket = FakeSocket([b"+PONG\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 6379)

        self.assertEqual(result["code"], "REDIS_PING_RESPONSE_OBSERVED")
        self.assertEqual(fake_socket.sent, [b"*1\r\n$4\r\nPING\r\n"])
        self.assertIn("読み取り専用", result["note"])

    @patch("engine.legacy_ports.socket.create_connection")
    def test_redis_noauth_response_is_observed_without_credentials(self, mock_connect):
        fake_socket = FakeSocket([b"-NOAUTH Authentication required.\r\n"])
        mock_connect.return_value = fake_socket

        result = probe_service_banner("example.test", 6379)

        self.assertEqual(result["code"], "REDIS_AUTH_REQUIRED_RESPONSE_OBSERVED")
        self.assertEqual(fake_socket.sent, [b"*1\r\n$4\r\nPING\r\n"])

    @patch("engine.legacy_ports.socket.create_connection")
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

        observation = Observation.ok("ports", "127.0.0.1", {
            "ports": [{"port": 22, "state": "open", "banner": None,
                       "peer": "127.0.0.1", "scope": "LOOPBACK",
                       "error": None, "conventional": "ssh"}],
        })
        with patch("engine.legacy_ports.scan.collect", return_value=observation), \
                patch("engine.legacy_ports.probe_service_banner",
                      return_value=probe_result):
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
