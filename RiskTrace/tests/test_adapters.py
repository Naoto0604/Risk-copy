import unittest

from engine.adapters import (
    DEFAULT_COLLECTOR,
    from_legacy_finding,
    from_legacy_findings,
    observations_from_checker,
)


def legacy_finding(**overrides):
    finding = {
        "type": "HEADER_CHECK",
        "subtype": "X-Frame-Options",
        "severity": "LOW",
        "title": "X-Frame-Optionsが設定されていません",
        "url": "https://example.test/",
        "description": "クリックジャッキングの可能性",
        "evidence": "X-Frame-Options=absent",
        "recommendation": "DENY を付与する",
    }
    finding.update(overrides)
    return finding


class TestFromLegacyFinding(unittest.TestCase):

    def test_result_is_a_usable_ok_observation(self):
        obs = from_legacy_finding(legacy_finding())
        self.assertTrue(obs.is_ok)
        self.assertTrue(obs.usable)
        self.assertIsNone(obs.note)
        self.assertIsNone(obs.evidence_id)

    def test_subject_comes_from_url(self):
        self.assertEqual(from_legacy_finding(legacy_finding()).subject, "https://example.test/")

    def test_collector_comes_from_type_lowercased(self):
        self.assertEqual(from_legacy_finding(legacy_finding()).collector, "header_check")

    def test_explicit_collector_wins(self):
        obs = from_legacy_finding(legacy_finding(), collector="http_headers")
        self.assertEqual(obs.collector, "http_headers")

    def test_blank_explicit_collector_is_rejected(self):
        with self.assertRaises(ValueError):
            from_legacy_finding(legacy_finding(), collector="  ")

    def test_missing_type_falls_back_to_default_collector(self):
        finding = legacy_finding()
        del finding["type"]
        self.assertEqual(from_legacy_finding(finding).collector, DEFAULT_COLLECTOR)

    def test_whitelisted_keys_are_copied(self):
        data = from_legacy_finding(legacy_finding()).data
        for key in ("type", "subtype", "title", "description", "evidence", "recommendation"):
            self.assertIn(key, data)

    def test_unknown_keys_are_not_copied(self):
        data = from_legacy_finding(legacy_finding(internal_debug="xyz")).data
        self.assertNotIn("internal_debug", data)

    def test_severity_rides_along_uppercased(self):
        self.assertEqual(from_legacy_finding(legacy_finding(severity="low")).data["severity"], "LOW")

    def test_missing_severity_is_tolerated(self):
        finding = legacy_finding()
        del finding["severity"]
        self.assertNotIn("severity", from_legacy_finding(finding).data)

    def test_legacy_flag_is_set(self):
        self.assertIs(from_legacy_finding(legacy_finding()).data["legacy"], True)

    def test_missing_url_is_rejected(self):
        finding = legacy_finding()
        del finding["url"]
        with self.assertRaises(ValueError):
            from_legacy_finding(finding)

    def test_blank_url_is_rejected(self):
        with self.assertRaises(ValueError):
            from_legacy_finding(legacy_finding(url="  "))

    def test_non_mapping_is_rejected(self):
        with self.assertRaises(TypeError):
            from_legacy_finding(["not", "a", "mapping"])

    def test_empty_string_values_are_skipped(self):
        data = from_legacy_finding(legacy_finding(description="  ")).data
        self.assertNotIn("description", data)

    def test_secrets_in_evidence_are_masked_by_the_contract(self):
        finding = legacy_finding(authorization="Bearer SECRETTOKEN")
        self.assertEqual(from_legacy_finding(finding).data["authorization"], "Bearer <masked>")

    def test_secret_key_with_non_string_value_is_skipped(self):
        data = from_legacy_finding(legacy_finding(api_key={"nested": "x"})).data
        self.assertNotIn("api_key", data)

    def test_secret_key_is_matched_case_insensitively(self):
        data = from_legacy_finding(legacy_finding(**{"X-Api-Key": "abc"})).data
        self.assertEqual(data["X-Api-Key"], "<masked>")


class TestBulk(unittest.TestCase):

    def test_order_is_preserved(self):
        observations = from_legacy_findings([
            legacy_finding(subtype="A", url="https://example.test/a"),
            legacy_finding(subtype="B", url="https://example.test/b"),
        ])
        self.assertEqual([o.data["subtype"] for o in observations], ["A", "B"])

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(from_legacy_findings([]), [])
        self.assertEqual(from_legacy_findings(None), [])

    def test_checker_adapter_passes_response_through(self):
        seen = []

        def checker(response):
            seen.append(response)
            return [legacy_finding()]

        observations = observations_from_checker(checker, "FAKE_RESPONSE", collector="http_headers")
        self.assertEqual(seen, ["FAKE_RESPONSE"])
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].collector, "http_headers")

    def test_checker_returning_nothing_yields_no_observations(self):
        self.assertEqual(observations_from_checker(lambda r: [], object()), [])


if __name__ == "__main__":
    unittest.main()