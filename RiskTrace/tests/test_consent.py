import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database import db as db_module
from verification import consent
from verification.consent import ACTIVE, EXPIRED, WITHDRAWN, ConsentError
from verification.scope import Scope


def make_scope(hosts=("example.test",), **overrides):
    return Scope(hosts=frozenset(hosts), ports=frozenset({443}), **overrides)


class ConsentTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False
        consent.init_consents()

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def grant(self, **overrides):
        params = {
            "grantor": "山田太郎",
            "contact": "yamada@example.test",
            "target": "example.test",
            "scope": make_scope(),
            "allowed_collectors": ["http_headers", "cookies"],
        }
        params.update(overrides)
        return consent.grant(**params)


class TestGrant(ConsentTestCase):

    def test_records_all_required_fields(self):
        record = self.grant(note="初回同意")
        self.assertEqual(record.grantor, "山田太郎")
        self.assertEqual(record.contact, "yamada@example.test")
        self.assertEqual(record.target, "example.test")
        self.assertEqual(record.status, ACTIVE)
        self.assertEqual(record.allowed_collectors, ("http_headers", "cookies"))
        self.assertEqual(record.note, "初回同意")
        self.assertIsNotNone(record.granted_at)
        self.assertIsNone(record.withdrawn_at)

    def test_target_is_normalized(self):
        self.assertEqual(self.grant(target=" Example.TEST. ").target, "example.test")

    def test_blank_grantor_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(grantor="  ")

    def test_blank_contact_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(contact="")

    def test_empty_collectors_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(allowed_collectors=[])

    def test_collectors_must_not_be_a_bare_string(self):
        with self.assertRaises(ConsentError):
            self.grant(allowed_collectors="http_headers")

    def test_blank_collector_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(allowed_collectors=["http_headers", " "])

    def test_target_must_be_inside_scope(self):
        with self.assertRaises(ConsentError):
            self.grant(target="other.test")

    def test_invalid_scope_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(scope={"hosts": frozenset(), "ports": frozenset({443})})

    def test_zero_expiry_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(expires_in_days=0)


class TestBudgets(ConsentTestCase):

    def test_defaults_are_stored(self):
        record = self.grant()
        self.assertEqual(record.budgets["requests"], 300.0)
        self.assertEqual(record.budgets["max_inflight"], 2.0)

    def test_overrides_are_applied(self):
        record = self.grant(budgets={"requests": 50, "per_host_interval": 1.5})
        self.assertEqual(record.budgets["requests"], 50.0)
        self.assertEqual(record.budgets["per_host_interval"], 1.5)

    def test_unknown_key_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(budgets={"timeout": 5})

    def test_zero_value_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(budgets={"requests": 0})

    def test_non_numeric_value_is_rejected(self):
        with self.assertRaises(ConsentError):
            self.grant(budgets={"requests": "many"})


class TestWithdraw(ConsentTestCase):

    def test_withdraw_marks_status_and_time(self):
        record = self.grant()
        consent.withdraw(record.id, reason="作業終了")
        stored = consent.get_consent(record.id)
        self.assertEqual(stored.status, WITHDRAWN)
        self.assertIsNotNone(stored.withdrawn_at)
        self.assertEqual(stored.note, "作業終了")

    def test_withdrawn_consent_is_not_active(self):
        record = self.grant()
        consent.withdraw(record.id)
        self.assertFalse(consent.is_active(record.id))
        self.assertEqual(consent.active_for("example.test"), [])

    def test_withdraw_twice_is_rejected(self):
        record = self.grant()
        consent.withdraw(record.id)
        with self.assertRaises(ConsentError):
            consent.withdraw(record.id)


class TestExpiry(ConsentTestCase):

    def expire(self, consent_id):
        conn = db_module.get_connection()
        try:
            conn.execute(
                "UPDATE consents SET expires_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds"), consent_id),
            )
            conn.commit()
        finally:
            conn.close()

    def test_expired_consent_is_not_active(self):
        record = self.grant()
        self.expire(record.id)
        self.assertFalse(consent.is_active(record.id))
        self.assertEqual(consent.active_for("example.test"), [])

    def test_expire_overdue_marks_row(self):
        record = self.grant()
        self.expire(record.id)
        self.assertEqual(consent.expire_overdue(), 1)
        self.assertEqual(consent.get_consent(record.id).status, EXPIRED)


class TestLookup(ConsentTestCase):

    def test_active_for_returns_only_that_target(self):
        self.grant()
        self.grant(target="other.test", scope=make_scope(("other.test",)))
        self.assertEqual(len(consent.active_for("example.test")), 1)

    def test_active_for_is_normalized(self):
        self.grant()
        self.assertEqual(len(consent.active_for(" EXAMPLE.test. ")), 1)

    def test_unknown_id_returns_none(self):
        self.assertIsNone(consent.get_consent("cns_missing"))

    def test_list_consents_filters_by_target(self):
        self.grant()
        self.grant(target="other.test", scope=make_scope(("other.test",)))
        self.assertEqual(len(consent.list_consents("example.test")), 1)


class TestScopeRoundTrip(ConsentTestCase):

    def test_scope_can_be_rebuilt(self):
        record = self.grant(scope=make_scope(path_prefixes=("/app",), allow_private=False))
        rebuilt = record.build_scope()
        self.assertTrue(rebuilt.allows("https://example.test/app/x"))
        self.assertFalse(rebuilt.allows("https://example.test/other"))

    def test_private_permission_is_preserved(self):
        record = self.grant(scope=make_scope(private_cidrs=("10.0.0.0/8",)))
        self.assertTrue(record.build_scope().allows_address("10.1.1.1"))


if __name__ == "__main__":
    unittest.main()