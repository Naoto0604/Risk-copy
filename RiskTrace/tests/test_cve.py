import unittest
from unittest.mock import patch

from engine.cve import lookup_from_observations
from engine.observations import Observation

NVD_DATA = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-0001",
                "vulnStatus": "Analyzed",
                "published": "2021-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "MySQL Server issue."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "AV:N"}}]},
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:oracle:mysql:8.0.25:*:*:*:*:*:*:*"}]}]}
                ],
            }
        }
    ]
}

EMPTY_DATA = {"vulnerabilities": [], "totalResults": 0, "source_url": "x", "error": None}


def ports_observation(banner="8.0.25-0ubuntu0.20.04.2", port=3306, state="open"):
    return Observation.ok(
        "ports",
        "127.0.0.1",
        {"host": "127.0.0.1", "ports": [{"port": port, "state": state, "banner": banner}]},
    )


class TestLookupFromObservations(unittest.TestCase):

    def test_candidate_becomes_a_finding(self):
        with patch("engine.cve._fetch_nvd_by_cpe", return_value=NVD_DATA):
            findings = lookup_from_observations([ports_observation()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "cve:CVE_VERSION_CANDIDATE")
        self.assertEqual(findings[0].severity, "INFO")
        self.assertIn("CVE-2021-0001", findings[0].title)

    def test_status_finding_becomes_a_finding(self):
        with patch("engine.cve._fetch_nvd_by_cpe", return_value=EMPTY_DATA):
            findings = lookup_from_observations([ports_observation()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "cve:NO_CVE_MATCH_FOUND")

    def test_ssh_banner_is_recognised(self):
        observation = ports_observation("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", port=22)
        with patch("engine.cve._fetch_nvd_by_cpe", return_value=EMPTY_DATA) as fetch:
            lookup_from_observations([observation])
        self.assertIn("openbsd:openssh:8.9p1", fetch.call_args[0][0])

    def test_port_without_banner_is_skipped(self):
        with patch("engine.cve._fetch_nvd_by_cpe") as fetch:
            self.assertEqual(lookup_from_observations([ports_observation(banner=None)]), [])
        fetch.assert_not_called()

    def test_closed_port_is_skipped(self):
        with patch("engine.cve._fetch_nvd_by_cpe") as fetch:
            self.assertEqual(
                lookup_from_observations([ports_observation(state="closed")]), []
            )
        fetch.assert_not_called()

    def test_other_collector_is_ignored(self):
        other = Observation.ok("http_headers", "example.test", {"host": "example.test"})
        with patch("engine.cve._fetch_nvd_by_cpe") as fetch:
            self.assertEqual(lookup_from_observations([other]), [])
        fetch.assert_not_called()

    def test_failure_is_swallowed(self):
        with patch("engine.cve._fetch_nvd_by_cpe", side_effect=RuntimeError("boom")):
            findings = lookup_from_observations([ports_observation()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "cve:NVD_LOOKUP_UNAVAILABLE")

    def test_unexpected_error_returns_empty(self):
        with patch("engine.cve.lookup_cve_candidates", side_effect=ValueError("x")):
            self.assertEqual(lookup_from_observations([ports_observation()]), [])


if __name__ == "__main__":
    unittest.main()