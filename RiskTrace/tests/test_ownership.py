import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database import db as db_module
from verification import ownership
from verification.ownership import (
    DNS_TXT,
    EXPIRED,
    FAILED,
    HTTP_FILE,
    PENDING,
    VERIFIED,
    FetchResult,
    ProofError,
)


def doh_answer(*values):
    return FetchResult(200, json.dumps({
        "Status": 0,
        "Answer": [{"name": "_risktrace.example.test", "type": 16, "TTL": 300, "data": f'"{v}"'} for v in values],
    }))


class ProofTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False
        ownership.init_proofs()

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def dns_challenge(self, host="example.test"):
        return ownership.create_challenge(host, DNS_TXT)

    def file_challenge(self, host="example.test"):
        return ownership.create_challenge(host, HTTP_FILE, base_url="https://example.test")


class TestCreation(ProofTestCase):

    def test_dns_challenge_has_record_name_and_token(self):
        challenge = self.dns_challenge()
        self.assertEqual(challenge.record_name, "_risktrace.example.test")
        self.assertEqual(challenge.status, PENDING)
        self.assertGreaterEqual(len(challenge.token), 40)

    def test_tokens_differ_between_challenges(self):
        self.assertNotEqual(self.dns_challenge().token, self.dns_challenge().token)

    def test_file_challenge_has_url_containing_token(self):
        challenge = self.file_challenge()
        self.assertIn(challenge.token, challenge.file_url)
        self.assertTrue(challenge.file_url.startswith("https://example.test/.well-known/risktrace/"))

    def test_file_challenge_requires_base_url(self):
        with self.assertRaises(ProofError):
            ownership.create_challenge("example.test", HTTP_FILE)

    def test_unknown_method_is_rejected(self):
        with self.assertRaises(ProofError):
            ownership.create_challenge("example.test", "email")

    def test_host_is_normalized(self):
        self.assertEqual(ownership.create_challenge(" Example.TEST. ", DNS_TXT).host, "example.test")

    def test_blank_host_is_rejected(self):
        with self.assertRaises(ProofError):
            ownership.create_challenge("  ", DNS_TXT)

    def test_setup_instructions_include_secret(self):
        challenge = self.dns_challenge()
        self.assertEqual(challenge.setup_instructions()["record_value"],
                         "risktrace-verify=" + challenge.token)

    def test_report_dict_hides_token_by_default(self):
        self.assertNotIn("token", self.dns_challenge().to_dict())

    def test_report_dict_can_include_token(self):
        challenge = self.dns_challenge()
        self.assertEqual(challenge.to_dict(include_token=True)["token"], challenge.token)


class TestDnsVerification(ProofTestCase):

    def test_matching_txt_verifies(self):
        challenge = self.dns_challenge()
        ok = ownership.verify_dns_txt(
            challenge.id,
            lambda url: doh_answer("risktrace-verify=" + challenge.token),
        )
        self.assertTrue(ok)
        self.assertEqual(ownership.get_challenge(challenge.id).status, VERIFIED)

    def test_matching_value_among_others_verifies(self):
        challenge = self.dns_challenge()
        ok = ownership.verify_dns_txt(
            challenge.id,
            lambda url: doh_answer("v=spf1 -all", "risktrace-verify=" + challenge.token),
        )
        self.assertTrue(ok)

    def test_partial_token_does_not_verify(self):
        challenge = self.dns_challenge()
        ok = ownership.verify_dns_txt(
            challenge.id,
            lambda url: doh_answer("risktrace-verify=" + challenge.token[:-4]),
        )
        self.assertFalse(ok)

    def test_missing_record_fails(self):
        challenge = self.dns_challenge()
        self.assertFalse(ownership.verify_dns_txt(challenge.id, lambda url: doh_answer()))
        self.assertEqual(ownership.get_challenge(challenge.id).status, FAILED)

    def test_query_url_targets_the_record(self):
        challenge = self.dns_challenge()
        seen = []

        def fetch(url):
            seen.append(url)
            return doh_answer("risktrace-verify=" + challenge.token)

        ownership.verify_dns_txt(challenge.id, fetch)
        self.assertIn("name=_risktrace.example.test", seen[0])
        self.assertIn("type=TXT", seen[0])

    def test_http_error_fails(self):
        challenge = self.dns_challenge()
        self.assertFalse(ownership.verify_dns_txt(challenge.id, lambda url: FetchResult(503, "")))

    def test_broken_json_fails(self):
        challenge = self.dns_challenge()
        self.assertFalse(ownership.verify_dns_txt(challenge.id, lambda url: FetchResult(200, "not json")))

    def test_network_exception_fails(self):
        challenge = self.dns_challenge()

        def boom(url):
            raise OSError("no route")

        self.assertFalse(ownership.verify_dns_txt(challenge.id, boom))

    def test_attempts_are_counted(self):
        challenge = self.dns_challenge()
        ownership.verify_dns_txt(challenge.id, lambda url: doh_answer())
        ownership.verify_dns_txt(challenge.id, lambda url: doh_answer())
        self.assertEqual(ownership.get_challenge(challenge.id).attempts, 2)


class TestFileVerification(ProofTestCase):

    def test_exact_body_verifies(self):
        challenge = self.file_challenge()
        ok = ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        self.assertTrue(ok)
        self.assertEqual(ownership.get_challenge(challenge.id).status, VERIFIED)

    def test_surrounding_whitespace_is_tolerated(self):
        challenge = self.file_challenge()
        ok = ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, f"\n{challenge.token}\n"))
        self.assertTrue(ok)

    def test_wrong_body_fails(self):
        challenge = self.file_challenge()
        self.assertFalse(ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, "nope")))

    def test_404_fails(self):
        challenge = self.file_challenge()
        self.assertFalse(ownership.verify_http_file(challenge.id, lambda url: FetchResult(404, challenge.token)))

    def test_fetch_uses_the_challenge_url(self):
        challenge = self.file_challenge()
        seen = []

        def fetch(url):
            seen.append(url)
            return FetchResult(200, challenge.token)

        ownership.verify_http_file(challenge.id, fetch)
        self.assertEqual(seen, [challenge.file_url])


class TestExpiry(ProofTestCase):

    def expire(self, proof_id):
        conn = db_module.get_connection()
        try:
            conn.execute(
                "UPDATE proofs SET expires_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds"), proof_id),
            )
            conn.commit()
        finally:
            conn.close()

    def test_expired_challenge_cannot_be_verified(self):
        challenge = self.dns_challenge()
        self.expire(challenge.id)
        with self.assertRaises(ProofError):
            ownership.verify_dns_txt(challenge.id, lambda url: doh_answer("risktrace-verify=" + challenge.token))

    def test_expired_challenge_is_marked_expired(self):
        challenge = self.dns_challenge()
        self.expire(challenge.id)
        with self.assertRaises(ProofError):
            ownership.verify_dns_txt(challenge.id, lambda url: doh_answer())
        self.assertEqual(ownership.get_challenge(challenge.id).status, EXPIRED)

    def test_expired_proof_is_not_valid(self):
        challenge = self.file_challenge()
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        self.assertTrue(ownership.is_valid("example.test"))
        self.expire(challenge.id)
        self.assertFalse(ownership.is_valid("example.test"))

    def test_verified_proof_is_valid(self):
        challenge = self.file_challenge()
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        self.assertTrue(ownership.is_valid("example.test"))

    def test_expire_overdue_marks_rows(self):
        challenge = self.file_challenge()
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        self.expire(challenge.id)
        self.assertEqual(ownership.expire_overdue(), 1)
        self.assertEqual(ownership.get_challenge(challenge.id).status, EXPIRED)


class TestHostScope(ProofTestCase):

    def test_proof_is_per_host(self):
        challenge = self.file_challenge("a.test")
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        self.assertTrue(ownership.is_valid("a.test"))
        self.assertFalse(ownership.is_valid("b.test"))

    def test_subdomain_is_not_covered_by_parent_proof(self):
        challenge = self.file_challenge("example.test")
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        self.assertFalse(ownership.is_valid("sub.example.test"))

    def test_method_filter_applies(self):
        challenge = self.file_challenge()
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        self.assertTrue(ownership.is_valid("example.test", HTTP_FILE))
        self.assertFalse(ownership.is_valid("example.test", DNS_TXT))


class TestMismatch(ProofTestCase):

    def test_method_mismatch_is_rejected(self):
        challenge = self.dns_challenge()
        with self.assertRaises(ProofError):
            ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))

    def test_unknown_id_is_rejected(self):
        with self.assertRaises(ProofError):
            ownership.verify_dns_txt("prf_missing", lambda url: doh_answer())


if __name__ == "__main__":
    unittest.main()