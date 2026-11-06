import unittest
from dataclasses import FrozenInstanceError

from engine.observations import (
    MASKED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_SKIPPED,
    Observation,
    is_secret_name,
    mask_header_value,
    mask_headers,
)


class TestStatusContract(unittest.TestCase):

    def test_unknown_status_is_rejected(self):
        with self.assertRaises(ValueError):
            Observation(
                collector="http_headers",
                subject="https://example.test/",
                status="done",
            )

    def test_status_must_not_be_empty(self):
        with self.assertRaises(ValueError):
            Observation(
                collector="http_headers",
                subject="https://example.test/",
                status="",
            )

    def test_ok_is_usable(self):
        obs = Observation.ok("http_headers", "https://example.test/")
        self.assertTrue(obs.usable)
        self.assertTrue(obs.is_ok)
        self.assertFalse(obs.is_error)
        self.assertFalse(obs.is_skipped)

    def test_error_stays_usable_but_is_distinguishable(self):
        """error は「検出なし」ではない。usable のまま status で区別する。"""
        obs = Observation.error("http_headers", "https://example.test/", "接続がタイムアウトした")
        self.assertTrue(obs.usable)
        self.assertTrue(obs.is_error)
        self.assertFalse(obs.is_ok)

    def test_skipped_is_not_usable(self):
        obs = Observation.skipped("dns", "example.test", "予算切れのため未実行")
        self.assertFalse(obs.usable)
        self.assertTrue(obs.is_skipped)

    def test_error_requires_note(self):
        with self.assertRaises(ValueError):
            Observation(collector="tls", subject="https://example.test/", status=STATUS_ERROR)

    def test_skipped_requires_note(self):
        with self.assertRaises(ValueError):
            Observation(collector="tls", subject="https://example.test/", status=STATUS_SKIPPED)

    def test_ok_does_not_require_note(self):
        obs = Observation(collector="tls", subject="https://example.test/", status=STATUS_OK)
        self.assertIsNone(obs.note)

    def test_blank_note_is_not_accepted_as_reason(self):
        with self.assertRaises(ValueError):
            Observation(
                collector="tls",
                subject="https://example.test/",
                status=STATUS_SKIPPED,
                note="   ",
            )


class TestRequiredFields(unittest.TestCase):

    def test_empty_collector_is_rejected(self):
        with self.assertRaises(ValueError):
            Observation.ok("", "https://example.test/")

    def test_empty_subject_is_rejected(self):
        with self.assertRaises(ValueError):
            Observation.ok("http_headers", "  ")

    def test_data_must_be_dict(self):
        with self.assertRaises(TypeError):
            Observation(
                collector="http_headers",
                subject="https://example.test/",
                status=STATUS_OK,
                data=["headers"],
            )

    def test_evidence_id_must_not_be_blank(self):
        with self.assertRaises(ValueError):
            Observation.ok("http_headers", "https://example.test/", evidence_id="  ")


class TestHeaderNormalization(unittest.TestCase):

    def test_header_names_are_lowercased(self):
        obs = Observation.ok(
            "http_headers",
            "https://example.test/",
            {"headers": {"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'"}},
        )
        self.assertEqual(
            obs.data["headers"],
            {"x-frame-options": "DENY", "content-security-policy": "default-src 'self'"},
        )

    def test_missing_header_is_preserved_as_none(self):
        obs = Observation.ok(
            "http_headers",
            "https://example.test/",
            {"headers": {"strict-transport-security": None}},
        )
        self.assertIsNone(obs.data["headers"]["strict-transport-security"])

    def test_observed_values_are_not_rewritten(self):
        obs = Observation.ok(
            "http_headers",
            "https://example.test/",
            {"headers": {"x-frame-options": "SAMEORIGIN"}},
        )
        self.assertEqual(obs.data["headers"]["x-frame-options"], "SAMEORIGIN")

    def test_source_dict_is_not_mutated(self):
        source = {"headers": {"X-Frame-Options": "DENY"}}
        Observation.ok("http_headers", "https://example.test/", source)
        self.assertEqual(source, {"headers": {"X-Frame-Options": "DENY"}})


class TestMasking(unittest.TestCase):

    def test_bearer_token_keeps_only_the_scheme(self):
        obs = Observation.ok(
            "http_headers",
            "https://example.test/",
            {"headers": {"Authorization": "Bearer abc123SECRET"}},
        )
        self.assertEqual(obs.data["headers"]["authorization"], f"Bearer {MASKED}")

    def test_basic_scheme_is_kept(self):
        self.assertEqual(mask_header_value("Authorization", "Basic dXNlcjpwYXNz"), f"Basic {MASKED}")

    def test_unknown_scheme_is_fully_masked(self):
        self.assertEqual(mask_header_value("Authorization", "weirdvalue"), MASKED)

    def test_cookie_value_is_masked(self):
        obs = Observation.ok(
            "http_headers",
            "https://example.test/",
            {"headers": {"Set-Cookie": "sessionid=abc; HttpOnly"}},
        )
        self.assertEqual(obs.data["headers"]["set-cookie"], MASKED)

    def test_non_secret_header_is_untouched(self):
        self.assertEqual(mask_header_value("X-Frame-Options", "DENY"), "DENY")

    def test_none_is_preserved(self):
        self.assertIsNone(mask_header_value("Authorization", None))

    def test_secret_key_is_masked_outside_headers(self):
        obs = Observation.ok(
            "discovery",
            "https://example.test/",
            {"tokens": [{"name": "api_key", "api_key": "SUPERSECRET", "where": "/app.js"}]},
        )
        self.assertEqual(obs.data["tokens"][0]["api_key"], MASKED)
        self.assertEqual(obs.data["tokens"][0]["where"], "/app.js")

    def test_underscore_and_hyphen_forms_are_equivalent(self):
        for name in ("api_key", "api-key", "API-KEY", "x_api_key", "X-API-KEY"):
            self.assertTrue(is_secret_name(name), name)
            self.assertEqual(mask_header_value(name, "SUPERSECRET"), MASKED, name)

    def test_common_credential_keys_are_masked(self):
        obs = Observation.ok(
            "discovery",
            "https://example.test/",
            {"found": {"client_secret": "abc", "password": "hunter2", "region": "ap-northeast-1"}},
        )
        self.assertEqual(obs.data["found"]["client_secret"], MASKED)
        self.assertEqual(obs.data["found"]["password"], MASKED)
        self.assertEqual(obs.data["found"]["region"], "ap-northeast-1")

    def test_original_key_casing_is_preserved_in_output(self):
        obs = Observation.ok(
            "discovery",
            "https://example.test/",
            {"found": {"API_KEY": "abc"}},
        )
        self.assertIn("API_KEY", obs.data["found"])
        self.assertEqual(obs.data["found"]["API_KEY"], MASKED)

    def test_masking_is_idempotent(self):
        once = mask_headers({"Authorization": "Bearer secret"})
        twice = mask_headers(once)
        self.assertEqual(once, twice)


class TestImmutability(unittest.TestCase):

    def test_field_assignment_is_rejected(self):
        obs = Observation.ok("http_headers", "https://example.test/")
        with self.assertRaises(FrozenInstanceError):
            obs.status = STATUS_ERROR

    def test_data_dict_is_shared_but_replaced_on_derivation(self):
        obs = Observation.ok("http_headers", "https://example.test/", {"headers": {"a": "b"}})
        derived = obs.with_evidence("ev_1")
        self.assertEqual(derived.data, obs.data)
        self.assertEqual(derived.observation_id, obs.observation_id)
        self.assertIsNone(obs.evidence_id)
        self.assertEqual(derived.evidence_id, "ev_1")


class TestIdentity(unittest.TestCase):

    def test_ids_are_unique(self):
        first = Observation.ok("http_headers", "https://example.test/")
        second = Observation.ok("http_headers", "https://example.test/")
        self.assertNotEqual(first.observation_id, second.observation_id)
        self.assertTrue(first.observation_id.startswith("ob_"))


class TestSerialization(unittest.TestCase):

    def test_to_dict_contains_contract_keys(self):
        obs = Observation.ok("http_headers", "https://example.test/")
        payload = obs.to_dict()
        self.assertEqual(
            set(payload),
            {
                "observation_id",
                "collector",
                "subject",
                "status",
                "data",
                "note",
                "evidence_id",
                "usable",
            },
        )
        self.assertTrue(payload["usable"])

    def test_round_trip_preserves_fields(self):
        original = Observation.error(
            "tls",
            "https://example.test/",
            "証明書検証に失敗した",
            data={"tls_version": "TLSv1.2"},
            evidence_id="ev_abc",
        )
        restored = Observation.from_dict(original.to_dict())
        self.assertEqual(restored.collector, original.collector)
        self.assertEqual(restored.subject, original.subject)
        self.assertEqual(restored.status, original.status)
        self.assertEqual(restored.note, original.note)
        self.assertEqual(restored.evidence_id, original.evidence_id)
        self.assertEqual(restored.observation_id, original.observation_id)
        self.assertTrue(restored.is_error)

    def test_round_trip_recomputes_usable(self):
        payload = Observation.ok("http_headers", "https://example.test/").to_dict()
        payload["usable"] = False
        self.assertTrue(Observation.from_dict(payload).usable)

    def test_from_dict_validates_status(self):
        payload = Observation.ok("http_headers", "https://example.test/").to_dict()
        payload["status"] = "finished"
        with self.assertRaises(ValueError):
            Observation.from_dict(payload)


class TestContractSeparation(unittest.TestCase):
    """Collector が判定情報を混ぜても契約は壊れない（移行期間の互換確認）。"""

    def test_severity_and_confidence_may_ride_along(self):
        obs = Observation.ok(
            "http_headers",
            "https://example.test/",
            {"headers": {}, "severity": "LOW", "confidence": "high"},
        )
        self.assertEqual(obs.data["severity"], "LOW")
        self.assertEqual(obs.data["confidence"], "high")


if __name__ == "__main__":
    unittest.main()