import socket
import ssl
import unittest

from collectors.tls import probe
from engine.scheduler import Budgets, Scheduler


def scheduler():
    instance = Scheduler(Budgets(per_host_interval=0.001))
    instance.start()
    return instance


def details(**overrides):
    base = {
        "present": True,
        "der_length": 1200,
        "subject_cn": "example.test",
        "issuer_cn": "Test CA",
        "issuer_org": "Test Org",
        "san": ["example.test", "www.example.test"],
        "not_before": "Jan  1 00:00:00 2026 GMT",
        "not_after": "Jan  1 00:00:00 2027 GMT",
        "days_until_expiry": 300,
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "cipher_bits": 128,
    }
    base.update(overrides)
    return base


def connect_ok(**overrides):
    calls = []

    def connect(host, port, *, verify, timeout):
        calls.append(verify)
        return details(**overrides)

    connect.calls = calls
    return connect


def connect_fail_then_ok():
    calls = []

    def connect(host, port, *, verify, timeout):
        calls.append(verify)
        if verify:
            raise ssl.SSLCertVerificationError(1, "certificate has expired")
        return details(subject_cn=None)

    connect.calls = calls
    return connect


class TestVerified(unittest.TestCase):

    def test_successful_handshake_is_verified(self):
        observation = probe.collect("https://example.test/", scheduler(), connect=connect_ok())
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["verification"], "VERIFIED")
        self.assertFalse(observation.data["retried_without_verification"])

    def test_protocol_and_cipher_are_recorded(self):
        observation = probe.collect("https://example.test/", scheduler(), connect=connect_ok())
        self.assertEqual(observation.data["protocol"], "TLSv1.3")
        self.assertEqual(observation.data["cipher_bits"], 128)

    def test_certificate_details_are_recorded(self):
        observation = probe.collect("https://example.test/", scheduler(), connect=connect_ok())
        certificate = observation.data["certificate"]
        self.assertEqual(certificate["issuer_cn"], "Test CA")
        self.assertIn("example.test", certificate["san"])
        self.assertEqual(certificate["days_until_expiry"], 300)

    def test_verification_is_attempted_first(self):
        connect = connect_ok()
        probe.collect("https://example.test/", scheduler(), connect=connect)
        self.assertEqual(connect.calls, [True])


class TestVerificationFailure(unittest.TestCase):

    def test_failure_keeps_failed_state(self):
        observation = probe.collect("https://example.test/", scheduler(),
                                    connect=connect_fail_then_ok())
        self.assertEqual(observation.data["verification"], "FAILED")
        self.assertTrue(observation.data["retried_without_verification"])

    def test_retry_is_unverified(self):
        connect = connect_fail_then_ok()
        probe.collect("https://example.test/", scheduler(), connect=connect)
        self.assertEqual(connect.calls, [True, False])

    def test_failed_verification_is_not_promoted(self):
        observation = probe.collect("https://example.test/", scheduler(),
                                    connect=connect_fail_then_ok())
        self.assertNotEqual(observation.data["verification"], "VERIFIED")

    def test_error_message_is_recorded(self):
        observation = probe.collect("https://example.test/", scheduler(),
                                    connect=connect_fail_then_ok())
        self.assertIn("expired", observation.data["verification_error"])

    def test_failure_still_yields_observation(self):
        observation = probe.collect("https://example.test/", scheduler(),
                                    connect=connect_fail_then_ok())
        self.assertTrue(observation.is_ok)


class TestErrors(unittest.TestCase):

    def test_handshake_error_becomes_error(self):
        def connect(host, port, *, verify, timeout):
            raise ssl.SSLError("handshake failure")

        observation = probe.collect("https://example.test/", scheduler(), connect=connect)
        self.assertTrue(observation.is_error)
        self.assertIn("SSLError", observation.note)

    def test_timeout_becomes_error(self):
        def connect(host, port, *, verify, timeout):
            raise socket.timeout("timed out")

        self.assertTrue(probe.collect("https://example.test/", scheduler(), connect=connect).is_error)

    def test_missing_host_becomes_error(self):
        self.assertTrue(probe.collect("https://", scheduler(), connect=connect_ok()).is_error)

    def test_http_url_is_skipped(self):
        observation = probe.collect("http://example.test/", scheduler(), connect=connect_ok())
        self.assertTrue(observation.is_skipped)
        self.assertIn("https", observation.note)


class TestControl(unittest.TestCase):

    def test_consumes_request_budget(self):
        instance = scheduler()
        probe.collect("https://example.test/", instance, connect=connect_ok())
        self.assertEqual(instance.usage()["request"], 1)

    def test_out_of_scope_is_error(self):
        instance = Scheduler(Budgets(per_host_interval=0.001), scope=lambda url: False)
        instance.start()
        self.assertTrue(probe.collect("https://example.test/", instance, connect=connect_ok()).is_error)

    def test_collector_does_not_decide_severity(self):
        observation = probe.collect("https://example.test/", scheduler(), connect=connect_ok())
        self.assertNotIn("severity", observation.data)


class TestCertParsing(unittest.TestCase):

    def test_unparseable_expiry_yields_none(self):
        self.assertIsNone(probe._parse_cert_time("not a date"))

    def test_expiry_is_parsed(self):
        parsed = probe._parse_cert_time("Jan  1 00:00:00 2027 GMT")
        self.assertEqual(parsed.year, 2027)


if __name__ == "__main__":
    unittest.main()