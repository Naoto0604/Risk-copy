import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database import db as db_module
from engine.observations import Observation
from evidence import store
from evidence.store import EvidenceError


class EvidenceTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = db_module.DB_DIR
        self._orig_path = db_module.DB_PATH
        self._orig_wal = db_module._wal_initialized

        db_module.DB_DIR = self._tmp.name
        db_module.DB_PATH = str(Path(self._tmp.name, "test.db"))
        db_module._wal_initialized = False
        store.init_evidence()

    def tearDown(self):
        db_module.DB_DIR = self._orig_dir
        db_module.DB_PATH = self._orig_path
        db_module._wal_initialized = self._orig_wal
        self._tmp.cleanup()

    def observation(self, **overrides):
        params = {
            "collector": "http_headers",
            "subject": "https://example.test/",
            "data": {"headers": {"x-frame-options": "DENY"}},
        }
        params.update(overrides)
        return Observation.ok(**params)


class TestSave(EvidenceTestCase):

    def test_saves_and_returns_record(self):
        record = store.save(self.observation(), job_id="job_1")
        self.assertTrue(record.id.startswith("ev_"))
        self.assertEqual(record.job_id, "job_1")
        self.assertEqual(record.collector, "http_headers")
        self.assertIsNotNone(record.expires_at)

    def test_ids_are_unique(self):
        self.assertNotEqual(store.save(self.observation()).id, store.save(self.observation()).id)

    def test_observation_id_is_recorded(self):
        observation = self.observation()
        record = store.save(observation)
        self.assertEqual(record.observation_id, observation.observation_id)

    def test_save_observation_links_back(self):
        observation = store.save_observation(self.observation())
        self.assertIsNotNone(observation.evidence_id)
        self.assertEqual(store.get(observation.evidence_id).collector, "http_headers")

    def test_non_observation_is_rejected(self):
        with self.assertRaises(EvidenceError):
            store.save({"collector": "x"})

    def test_zero_retention_is_rejected(self):
        with self.assertRaises(EvidenceError):
            store.save(self.observation(), retention_days=0)


class TestImmutability(EvidenceTestCase):

    def test_record_has_no_update_path(self):
        record = store.save(self.observation())
        before = store.get(record.id)
        store.save(self.observation())
        after = store.get(record.id)
        self.assertEqual(before.to_dict(), after.to_dict())

    def test_identical_content_yields_identical_hash(self):
        first = store.save(self.observation())
        second = store.save(self.observation())
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(first.sha256, second.sha256)

    def test_different_content_yields_different_hash(self):
        first = store.save(self.observation())
        second = store.save(self.observation(data={"headers": {"x-frame-options": "SAMEORIGIN"}}))
        self.assertNotEqual(first.sha256, second.sha256)

    def test_key_order_does_not_change_hash(self):
        first = store.save(self.observation(data={"a": 1, "b": 2}))
        second = store.save(self.observation(data={"b": 2, "a": 1}))
        self.assertEqual(first.sha256, second.sha256)


class TestIntegrity(EvidenceTestCase):

    def test_verify_passes_on_intact_record(self):
        record = store.save(self.observation())
        self.assertTrue(store.verify(record.id))

    def test_verify_detects_tampering(self):
        record = store.save(self.observation())
        conn = db_module.get_connection()
        try:
            conn.execute(
                "UPDATE evidence SET payload_json = ? WHERE id = ?",
                ('{"collector":"http_headers","subject":"https://example.test/","status":"ok","data":{"tampered":true},"note":null}', record.id),
            )
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(store.verify(record.id))

    def test_verify_on_missing_id_raises(self):
        with self.assertRaises(EvidenceError):
            store.verify("ev_missing")

    def test_verify_returns_false_when_hash_is_edited(self):
        record = store.save(self.observation())
        conn = db_module.get_connection()
        try:
            conn.execute("UPDATE evidence SET sha256 = 'deadbeef' WHERE id = ?", (record.id,))
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(store.verify(record.id))


class TestMasking(EvidenceTestCase):

    def test_secret_keys_are_masked_in_payload(self):
        record = store.save(self.observation(data={"authorization": "Bearer SECRET"}))
        self.assertEqual(record.payload["data"]["authorization"], "<masked>")
        self.assertNotIn("SECRET", str(record.payload))

    def test_nested_secret_keys_are_masked(self):
        record = store.save(self.observation(data={"found": {"api_key": "SECRET"}}))
        self.assertEqual(record.payload["data"]["found"]["api_key"], "<masked>")

    def test_observation_data_is_untouched(self):
        observation = self.observation(data={"x-api-key": "abc"})
        store.save(observation)
        self.assertEqual(observation.data["x-api-key"], "<masked>")


class TestLookup(EvidenceTestCase):

    def test_for_observation(self):
        observation = self.observation()
        store.save(observation)
        self.assertEqual(len(store.for_observation(observation.observation_id)), 1)

    def test_for_job(self):
        store.save(self.observation(), job_id="job_9")
        self.assertEqual(len(store.for_job("job_9")), 1)

    def test_count(self):
        store.save(self.observation())
        store.save(self.observation())
        self.assertEqual(store.count(), 2)

    def test_unknown_id_returns_none(self):
        self.assertIsNone(store.get("ev_missing"))


class TestRetention(EvidenceTestCase):

    def test_purge_removes_expired_only(self):
        old = store.save(self.observation())
        conn = db_module.get_connection()
        try:
            conn.execute(
                "UPDATE evidence SET expires_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="microseconds"), old.id),
            )
            conn.commit()
        finally:
            conn.close()

        fresh = store.save(self.observation())
        self.assertEqual(store.purge_expired(), 1)
        self.assertIsNone(store.get(old.id))
        self.assertIsNotNone(store.get(fresh.id))

    def test_purge_with_nothing_expired(self):
        store.save(self.observation())
        self.assertEqual(store.purge_expired(), 0)


class TestReport(EvidenceTestCase):

    def test_to_dict_exposes_id_and_hash(self):
        record = store.save(self.observation())
        payload = record.to_dict()
        self.assertEqual(payload["id"], record.id)
        self.assertIn("sha256", payload)
        self.assertIn("payload", payload)


if __name__ == "__main__":
    unittest.main()