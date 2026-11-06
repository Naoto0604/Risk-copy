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
