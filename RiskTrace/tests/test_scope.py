import unittest

from verification.scope import (
    Scope,
    ScopeError,
    build_checker,
    classify_ip,
    normalize_host,
)


def scope(**overrides):
    base = {"hosts": frozenset({"example.test"}), "ports": frozenset({443})}
    base.update(overrides)
    return Scope(**base)


def public_resolver(host):
    return ["93.184.216.34"]


def private_resolver(host):
    return ["192.168.1.10"]


def mixed_resolver(host):
    return ["93.184.216.34", "10.0.0.5"]


class TestDefinition(unittest.TestCase):

    def test_empty_hosts_is_rejected(self):
        with self.assertRaises(ScopeError):
            Scope(hosts=frozenset(), ports=frozenset({443}))

    def test_empty_ports_is_rejected(self):
        with self.assertRaises(ScopeError):
            Scope(hosts=frozenset({"a.test"}), ports=frozenset())

    def test_bad_port_is_rejected(self):
        with self.assertRaises(ScopeError):
            Scope(hosts=frozenset({"a.test"}), ports=frozenset({70000}))

    def test_bad_host_is_rejected(self):
        with self.assertRaises(ScopeError):
            Scope(hosts=frozenset({"bad host"}), ports=frozenset({443}))

    def test_path_prefix_must_start_with_slash(self):
        with self.assertRaises(ScopeError):
            scope(path_prefixes=("app",))

    def test_bad_cidr_is_rejected(self):
        with self.assertRaises(ScopeError):
            scope(private_cidrs=("10.0.0.0/99",))

    def test_hosts_are_normalized(self):
        self.assertEqual(scope(hosts=frozenset({"Example.TEST."})).hosts, frozenset({"example.test"}))


class TestHostMatching(unittest.TestCase):

    def test_exact_host_is_allowed(self):
        self.assertTrue(scope().allows("https://example.test/"))

    def test_subdomain_is_not_allowed(self):
        decision = scope().allows("https://sub.example.test/")
        self.assertFalse(decision)
        self.assertIn("スコープ外", decision.reason)

    def test_parent_domain_is_not_allowed(self):
        self.assertFalse(scope(hosts=frozenset({"sub.example.test"})).allows("https://example.test/"))

    def test_host_comparison_is_case_insensitive(self):
        self.assertTrue(scope().allows("https://EXAMPLE.test/"))

    def test_trailing_dot_is_ignored(self):
        self.assertTrue(scope().allows("https://example.test./"))

    def test_subdomain_can_be_allowed_explicitly(self):
        self.assertTrue(scope(hosts=frozenset({"a.test", "b.a.test"})).allows("https://b.a.test/"))

    def test_normalize_host_strips_and_lowercases(self):
        self.assertEqual(normalize_host("  A.TEST. "), "a.test")


class TestPortAndScheme(unittest.TestCase):

    def test_default_port_is_inferred(self):
        self.assertTrue(scope().allows("https://example.test/"))

    def test_disallowed_port_is_rejected(self):
        decision = scope().allows("https://example.test:8443/")
        self.assertFalse(decision)
        self.assertIn("ポート", decision.reason)

    def test_http_is_rejected_when_only_443_allowed(self):
        self.assertFalse(scope().allows("http://example.test/"))

    def test_http_is_allowed_when_80_is_in_scope(self):
        self.assertTrue(scope(ports=frozenset({80, 443})).allows("http://example.test/"))

    def test_non_http_scheme_is_rejected(self):
        self.assertFalse(scope().allows("ftp://example.test/"))


class TestPathMatching(unittest.TestCase):

    def test_root_prefix_allows_everything(self):
        self.assertTrue(scope().allows("https://example.test/anything/deep"))

    def test_restricted_prefix_allows_inside(self):
        restricted = scope(path_prefixes=("/app",))
        self.assertTrue(restricted.allows("https://example.test/app"))
        self.assertTrue(restricted.allows("https://example.test/app/x"))

    def test_restricted_prefix_rejects_outside(self):
        restricted = scope(path_prefixes=("/app",))
        self.assertFalse(restricted.allows("https://example.test/other"))

    def test_prefix_boundary_is_respected(self):
        restricted = scope(path_prefixes=("/app",))
        self.assertFalse(restricted.allows("https://example.test/application"))


class TestAddressPolicy(unittest.TestCase):

    def test_global_is_allowed(self):
        self.assertTrue(scope().allows_address("93.184.216.34"))

    def test_loopback_is_rejected_by_default(self):
        self.assertFalse(scope().allows_address("127.0.0.1"))

    def test_private_is_rejected_by_default(self):
        self.assertFalse(scope().allows_address("192.168.1.1"))

    def test_link_local_is_rejected(self):
        self.assertFalse(scope().allows_address("169.254.1.1"))

    def test_ipv6_loopback_is_rejected(self):
        self.assertFalse(scope().allows_address("::1"))

    def test_allow_private_permits_private(self):
        self.assertTrue(scope(allow_private=True).allows_address("10.0.0.1"))

    def test_allow_private_permits_loopback(self):
        self.assertTrue(scope(allow_private=True).allows_address("127.0.0.1"))

    def test_cidr_exception_permits_only_that_range(self):
        narrow = scope(private_cidrs=("10.1.0.0/16",))
        self.assertTrue(narrow.allows_address("10.1.2.3"))
        self.assertFalse(narrow.allows_address("10.2.2.3"))

    def test_cidr_exception_does_not_permit_loopback(self):
        self.assertFalse(scope(private_cidrs=("10.1.0.0/16",)).allows_address("127.0.0.1"))

    def test_invalid_address_is_rejected(self):
        self.assertFalse(scope().allows_address("not-an-ip"))

    def test_classify_ip_covers_classes(self):
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("10.0.0.1"), "private")
        self.assertEqual(classify_ip("169.254.0.1"), "link_local")
        self.assertEqual(classify_ip("93.184.216.34"), "global")
        self.assertEqual(classify_ip("nope"), "invalid")


class TestResolvedMatching(unittest.TestCase):

    def test_all_global_passes(self):
        self.assertTrue(scope().allows_resolved("example.test", ["93.184.216.34"]))

    def test_any_private_fails(self):
        decision = scope().allows_resolved("example.test", ["93.184.216.34", "10.0.0.5"])
        self.assertFalse(decision)
        self.assertIn("private", decision.reason)

    def test_empty_resolution_fails(self):
        decision = scope().allows_resolved("example.test", [])
        self.assertFalse(decision)
        self.assertIn("名前解決", decision.reason)

    def test_out_of_scope_host_fails_before_resolution(self):
        self.assertFalse(scope().allows_resolved("other.test", ["93.184.216.34"]))


class TestCheckAndChecker(unittest.TestCase):

    def test_check_raises_on_rejection(self):
        with self.assertRaises(ScopeError):
            scope().check("https://other.test/")

    def test_check_passes_silently(self):
        scope().check("https://example.test/")

    def test_checker_accepts_public_target(self):
        self.assertTrue(build_checker(scope(), public_resolver)("https://example.test/"))

    def test_checker_rejects_private_resolution(self):
        self.assertFalse(build_checker(scope(), private_resolver)("https://example.test/"))

    def test_checker_rejects_mixed_resolution(self):
        self.assertFalse(build_checker(scope(), mixed_resolver)("https://example.test/"))

    def test_checker_rejects_out_of_scope_url(self):
        self.assertFalse(build_checker(scope(), public_resolver)("https://other.test/"))

    def test_checker_returns_false_on_resolution_error(self):
        def boom(host):
            raise OSError("no dns")

        self.assertFalse(build_checker(scope(), boom)("https://example.test/"))


class TestDescribe(unittest.TestCase):

    def test_describe_lists_scope(self):
        described = scope(private_cidrs=("10.0.0.0/8",)).describe()
        self.assertEqual(described["hosts"], ["example.test"])
        self.assertEqual(described["private_cidrs"], ["10.0.0.0/8"])
        self.assertFalse(described["allow_private"])


if __name__ == "__main__":
    unittest.main()