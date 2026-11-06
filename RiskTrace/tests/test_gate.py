import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database import db as db_module
from verification import consent, gate, ownership
from verification.gate import GateError
from verification.ownership import DNS_TXT, HTTP_FILE, FetchResult
from verification.scope import Scope


def make_scope(hosts=("example.test",), **overrides):
    return Scope(hosts=frozenset(hosts), ports=frozenset({443}), **overrides)


class GateTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False

        ownership.init_proofs()
        consent.init_consents()

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def prove(self, host="example.test"):
        challenge = ownership.create_challenge(host, HTTP_FILE, base_url=f"https://{host}")
        ownership.verify_http_file(challenge.id, lambda url: FetchResult(200, challenge.token))
        return challenge

    def grant(self, target="example.test", scope=None, collectors=None):
        return consent.grant(
            grantor="山田太郎",
            contact="yamada@example.test",
            target=target,
            scope=scope or make_scope(),
            allowed_collectors=collectors or ["http_headers"],
        )

    def expire_consent(self, consent_id):
        conn = db_module.get_connection()
        try:
            conn.execute(
                "UPDATE consents SET expires_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds"), consent_id),
            )
            conn.commit()
        finally:
            conn.close()


class TestHappyPath(GateTestCase):

    def test_proof_and_consent_allows(self):
        self.prove()
        record = self.grant()
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reasons, ())
        self.assertIsNotNone(result.scope)
        self.assertIsNotNone(result.budgets)

    def test_target_is_normalized(self):
        self.prove()
        record = self.grant()
        self.assertTrue(gate.evaluate(" Example.TEST. ", consent_id=record.id).allowed)

    def test_ensure_returns_result(self):
        self.prove()
        record = self.grant()
        self.assertTrue(gate.ensure("example.test", consent_id=record.id).allowed)

    def test_budgets_come_from_consent(self):
        self.prove()
        record = consent.grant(
            grantor="a", contact="b", target="example.test", scope=make_scope(),
            allowed_collectors=["http_headers"], budgets={"requests": 42},
        )
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertEqual(result.budgets.requests, 42)

    def test_consented_result_is_not_proof_only(self):
        self.prove()
        record = self.grant()
        self.assertFalse(gate.evaluate("example.test", consent_id=record.id).proof_only)


class TestConsentGate(GateTestCase):

    def test_missing_consent_id_is_rejected(self):
        self.prove()
        result = gate.evaluate("example.test")
        self.assertFalse(result.allowed)
        self.assertIn("同意記録が指定されていません", result.reasons[0])

    def test_unknown_consent_id_is_rejected(self):
        self.prove()
        self.assertFalse(gate.evaluate("example.test", consent_id="cns_nope").allowed)

    def test_consent_for_other_target_is_rejected(self):
        self.prove("other.test")
        record = self.grant(target="other.test", scope=make_scope(("other.test",)))
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertFalse(result.allowed)

    def test_withdrawn_consent_is_rejected(self):
        self.prove()
        record = self.grant()
        consent.withdraw(record.id)
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertFalse(result.allowed)
        self.assertTrue(any("有効ではありません" in r for r in result.reasons))

    def test_expired_consent_is_rejected(self):
        self.prove()
        record = self.grant()
        self.expire_consent(record.id)
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertFalse(result.allowed)
        self.assertTrue(any("有効期限" in r for r in result.reasons))


class TestProofGate(GateTestCase):

    def test_missing_proof_is_rejected(self):
        record = self.grant()
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertFalse(result.allowed)
        self.assertTrue(any("所有証明" in r for r in result.reasons))

    def test_expired_proof_is_rejected(self):
        challenge = self.prove()
        record = self.grant()
        conn = db_module.get_connection()
        try:
            conn.execute(
                "UPDATE proofs SET expires_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds"), challenge.id),
            )
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(gate.evaluate("example.test", consent_id=record.id).allowed)

    def test_proof_only_path_works_without_consent(self):
        """§4.11: 証明確認の限定通信は proof のみで通る。"""
        self.prove()
        result = gate.evaluate("example.test", require=("proof",))
        self.assertTrue(result.allowed)
        self.assertIsNone(result.consent)
        self.assertTrue(result.proof_only)

    def test_proof_only_path_returns_minimal_scope(self):
        self.prove()
        result = gate.evaluate("example.test", require=("proof",))
        self.assertEqual(result.scope.hosts, frozenset({"example.test"}))
        self.assertEqual(result.scope.ports, frozenset({80, 443}))

    def test_proof_only_scope_rejects_other_hosts(self):
        self.prove()
        result = gate.evaluate("example.test", require=("proof",))
        self.assertFalse(result.scope.allows("https://other.test/"))

    def test_proof_only_blocks_diagnostic_collectors(self):
        self.prove()
        result = gate.evaluate("example.test", require=("proof",))
        self.assertFalse(result.allows_collector("http_headers"))

    def test_proof_only_path_still_needs_proof(self):
        self.assertFalse(gate.evaluate("example.test", require=("proof",)).allowed)

    def test_unknown_requirement_is_rejected(self):
        with self.assertRaises(ValueError):
            gate.evaluate("example.test", require=("ownership",))


class TestScopeConsistency(GateTestCase):
    """§4.12: 証明対象と同意対象の範囲が一致しなければ拒否。"""

    def test_scope_host_without_proof_is_rejected(self):
        self.prove("example.test")
        record = self.grant(scope=make_scope(("example.test", "extra.test")))
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertFalse(result.allowed)
        self.assertTrue(any("extra.test" in r for r in result.reasons))

    def test_all_scope_hosts_proven_allows(self):
        self.prove("example.test")
        self.prove("extra.test")
        record = self.grant(scope=make_scope(("example.test", "extra.test")))
        self.assertTrue(gate.evaluate("example.test", consent_id=record.id).allowed)

    def test_reasons_accumulate(self):
        record = self.grant(scope=make_scope(("example.test", "extra.test")))
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertGreaterEqual(len(result.reasons), 2)


class TestCollectorPermission(GateTestCase):

    def test_allowed_collector_passes(self):
        self.prove()
        record = self.grant(collectors=["http_headers"])
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertTrue(result.allows_collector("http_headers"))

    def test_unlisted_collector_fails(self):
        self.prove()
        record = self.grant(collectors=["http_headers"])
        result = gate.evaluate("example.test", consent_id=record.id)
        self.assertFalse(result.allows_collector("port_scan"))
        with self.assertRaises(GateError):
            result.require_collector("port_scan")


class TestScheduler(GateTestCase):

    def test_open_scheduler_uses_consent_budget(self):
        self.prove()
        record = self.grant()
        result = gate.ensure("example.test", consent_id=record.id)
        scheduler = gate.open_scheduler(result, resolver=lambda host: ["93.184.216.34"])
        self.assertEqual(scheduler.remaining("request"), int(record.budgets["requests"]))

    def test_scheduler_rejects_out_of_scope_url(self):
        self.prove()
        record = self.grant()
        result = gate.ensure("example.test", consent_id=record.id)
        scheduler = gate.open_scheduler(result, resolver=lambda host: ["93.184.216.34"])
        self.assertTrue(scheduler.scope_enforced)
        self.assertTrue(scheduler._scope("https://example.test/"))
        self.assertFalse(scheduler._scope("https://other.test/"))

    def test_scheduler_rejects_private_resolution(self):
        self.prove()
        record = self.grant()
        result = gate.ensure("example.test", consent_id=record.id)
        scheduler = gate.open_scheduler(result, resolver=lambda host: ["192.168.0.5"])
        self.assertFalse(scheduler._scope("https://example.test/"))

    def test_proof_only_result_can_open_scheduler(self):
        self.prove()
        result = gate.ensure("example.test", require=("proof",))
        scheduler = gate.open_scheduler(result, resolver=lambda host: ["93.184.216.34"])
        self.assertTrue(scheduler._scope("https://example.test/"))

    def test_open_scheduler_on_rejected_result_raises(self):
        with self.assertRaises(GateError):
            gate.open_scheduler(gate.evaluate("example.test"))


class TestReport(GateTestCase):

    def test_to_dict_lists_state(self):
        self.prove()
        record = self.grant()
        payload = gate.evaluate("example.test", consent_id=record.id).to_dict()
        self.assertTrue(payload["allowed"])
        self.assertEqual(payload["consent_id"], record.id)
        self.assertEqual(payload["collectors"], ["http_headers"])
        self.assertFalse(payload["proof_only"])


if __name__ == "__main__":
    unittest.main()