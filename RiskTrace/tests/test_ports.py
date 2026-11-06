import unittest

from collectors.ports import scan
from engine.scheduler import Budgets, Cancelled, Scheduler
from pathlib import Path

from engine import rule_runner
from engine import rules as rules_module
from engine.observations import Observation

HOST = "example.test"


def scheduler(scope=None, budgets=None):
    instance = Scheduler(
        budgets or Budgets(per_host_interval=0.001),
        scope=scope or (lambda url: True),
    )
    instance.start()
    return instance


def connect_from(table):
    """port -> (state, banner) の表から probe を作る。"""
    calls = []

    def probe(host, port, timeout):
        calls.append((host, port))
        return table.get(port, ("closed", None))

    probe.calls = calls
    return probe


def collect(table=None, target=HOST, **kwargs):
    return scan.collect(
        target,
        kwargs.pop("sched", None) or scheduler(),
        connect=connect_from(table or {}),
        **kwargs,
    )


class TestStates(unittest.TestCase):

    def test_open_port_is_recorded(self):
        observation = collect({443: ("open", None)}, ports=(443,))
        self.assertEqual(observation.data["ports"][0]["state"], "open")
        self.assertEqual(observation.data["open"], [443])

    def test_closed_port_is_recorded(self):
        observation = collect({80: ("closed", None)}, ports=(80,))
        self.assertEqual(observation.data["ports"][0]["state"], "closed")
        self.assertEqual(observation.data["open"], [])

    def test_filtered_port_is_recorded(self):
        observation = collect({22: ("filtered", None)}, ports=(22,))
        self.assertEqual(observation.data["ports"][0]["state"], "filtered")

    def test_banner_is_kept(self):
        observation = collect({22: ("open", "SSH-2.0-OpenSSH_8.9")}, ports=(22,))
        self.assertEqual(observation.data["ports"][0]["banner"], "SSH-2.0-OpenSSH_8.9")

    def test_conventional_label_is_attached(self):
        observation = collect({3306: ("open", None)}, ports=(3306,))
        self.assertEqual(observation.data["ports"][0]["conventional"], "mysql")

    def test_unknown_port_has_no_label(self):
        observation = collect({9999: ("open", None)}, ports=(9999,))
        self.assertIsNone(observation.data["ports"][0]["conventional"])

    def test_counts_are_summarised(self):
        observation = collect({80: ("open", None), 443: ("open", None)}, ports=(80, 443, 22))
        self.assertEqual(observation.data["counts"]["open"], 2)
        self.assertEqual(observation.data["counts"]["closed"], 1)


class TestScope(unittest.TestCase):

    def test_out_of_scope_port_is_not_probed(self):
        probe = connect_from({443: ("open", None)})
        scan.collect(
            HOST,
            scheduler(scope=lambda url: ":443/" in url),
            ports=(443, 80),
            connect=probe,
        )
        self.assertEqual([port for _host, port in probe.calls], [443])

    def test_out_of_scope_is_counted(self):
        observation = collect(
            {443: ("open", None)},
            ports=(443, 80),
            sched=scheduler(scope=lambda url: ":443/" in url),
        )
        self.assertEqual(observation.data["counts"]["out_of_scope"], 1)


class TestErrors(unittest.TestCase):

    def test_socket_error_is_recorded_and_continues(self):
        def probe(host, port, timeout):
            if port == 22:
                raise OSError("no route")
            return "open", None

        observation = scan.collect(HOST, scheduler(), ports=(22, 80), connect=probe)
        self.assertEqual(observation.data["ports"][0]["state"], "error")
        self.assertIn("no route", observation.data["ports"][0]["error"])
        self.assertEqual(observation.data["ports"][1]["state"], "open")

    def test_host_can_be_extracted_from_a_url(self):
        observation = scan.collect(
            "https://example.test/path", scheduler(), ports=(443,),
            connect=connect_from({443: ("open", None)}),
        )
        self.assertEqual(observation.subject, HOST)

    def test_missing_host_is_an_error(self):
        observation = scan.collect("", scheduler(), connect=connect_from({}))
        self.assertTrue(observation.is_error)

    def test_empty_port_list_is_an_error(self):
        observation = collect({}, ports=())
        self.assertTrue(observation.is_error)


class TestControl(unittest.TestCase):

    def test_each_port_costs_one_request(self):
        sched = scheduler()
        scan.collect(HOST, sched, ports=(80, 443), connect=connect_from({}))
        self.assertEqual(sched.usage()["request"], 2)

    def test_port_list_is_capped(self):
        observation = collect({}, ports=tuple(range(1, 100)))
        self.assertEqual(len(observation.data["ports"]), scan.MAX_PORTS)

    def test_budget_exhaustion_truncates_without_raising(self):
        observation = collect(
            {}, ports=(80, 443),
            sched=scheduler(budgets=Budgets(requests=1, per_host_interval=0.001)),
        )
        self.assertTrue(observation.is_ok)
        self.assertEqual(observation.data["truncated_reason"], "budget")

    def test_cancellation_propagates(self):
        sched = scheduler()
        sched.cancel("test")
        with self.assertRaises(Cancelled):
            scan.collect(HOST, sched, connect=connect_from({}))

    def test_no_verdict_is_recorded(self):
        observation = collect({80: ("open", None)}, ports=(80,))
        self.assertNotIn("severity", observation.data)
        self.assertNotIn("confidence", observation.data)

    def test_truncated_flag_defaults_to_false(self):
        observation = collect({80: ("open", None)}, ports=(80,))
        self.assertFalse(observation.data["truncated"])

class TestPeerScope(unittest.TestCase):

    def test_loopback_peer_is_classified(self):
        observation = collect({443: ("open", None, "127.0.0.1")}, ports=(443,))
        self.assertEqual(observation.data["ports"][0]["scope"], "LOOPBACK")

    def test_loopback_peer_lands_in_open_loopback(self):
        observation = collect({443: ("open", None, "127.0.0.1")}, ports=(443,))
        self.assertEqual(observation.data["open_loopback"], [443])
        self.assertEqual(observation.data["open_external"], [])

    def test_private_peer_lands_in_open_external(self):
        observation = collect({443: ("open", None, "10.0.0.5")}, ports=(443,))
        self.assertEqual(observation.data["open_external"], [443])

    def test_scope_counts_are_tallied(self):
        observation = collect(
            {443: ("open", None, "127.0.0.1"), 80: ("open", None, "10.0.0.5")},
            ports=(443, 80),
        )
        self.assertEqual(observation.data["scope_counts"], {"LOOPBACK": 1, "PRIVATE": 1})

    def test_two_element_probe_yields_unknown_scope(self):
        observation = collect({443: ("open", None)}, ports=(443,))
        self.assertEqual(observation.data["ports"][0]["scope"], "UNKNOWN")

    def test_closed_port_has_no_scope(self):
        observation = collect({443: ("closed", None, None)}, ports=(443,))
        self.assertIsNone(observation.data["ports"][0]["scope"])


class TestClassifyPeer(unittest.TestCase):

    def test_localhost_name(self):
        self.assertEqual(scan.classify_peer("localhost"), "LOOPBACK")

    def test_loopback_v4(self):
        self.assertEqual(scan.classify_peer("127.0.0.1"), "LOOPBACK")

    def test_loopback_v6(self):
        self.assertEqual(scan.classify_peer("::1"), "LOOPBACK")

    def test_link_local_with_scope_id(self):
        self.assertEqual(scan.classify_peer("fe80::1%12"), "LINK_LOCAL")

    def test_private_ranges(self):
        for address in ("10.1.2.3", "172.16.5.5", "192.168.0.10"):
            with self.subTest(address=address):
                self.assertEqual(scan.classify_peer(address), "PRIVATE")

    def test_documentation_range_is_unknown(self):
        self.assertEqual(scan.classify_peer("203.0.113.9"), "UNKNOWN")

    def test_public(self):
        self.assertEqual(scan.classify_peer("8.8.8.8"), "PUBLIC")

    def test_blank_is_unknown(self):
        self.assertEqual(scan.classify_peer(""), "UNKNOWN")
        self.assertEqual(scan.classify_peer(None), "UNKNOWN")

    def test_hostname_is_unknown(self):
        self.assertEqual(scan.classify_peer("example.test"), "UNKNOWN")


class TestScopeRules(unittest.TestCase):

    RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "ports"

    def ports(self, open_external=(), open_loopback=()):
        return Observation.ok("ports", HOST, {
            "open": list(open_external) + list(open_loopback),
            "open_external": list(open_external),
            "open_loopback": list(open_loopback),
            "scope_counts": {},
            "counts": {},
        })

    def ids(self, observation):
        normal, low = rule_runner.run(
            rules_module.load_rules_from_dir(self.RULES_DIR),
            [observation],
            satisfied=frozenset({"proof", "consent"}),
        )
        return sorted(f.rule_id for f in normal + low)

    def test_loopback_only_database_port_is_info(self):
        self.assertEqual(self.ids(self.ports(open_loopback=(3306,))),
                         ["ports.review-loopback-only"])

    def test_external_database_port_hits_the_specific_rule(self):
        found = self.ids(self.ports(open_external=(3306,)))
        self.assertIn("ports.database-open", found)
        self.assertNotIn("ports.review-loopback-only", found)

    def test_external_redis_hits_the_specific_rule(self):
        self.assertIn("ports.redis-open", self.ids(self.ports(open_external=(6379,))))

    def test_mixed_scope_hits_the_specific_rule(self):
        found = self.ids(self.ports(open_external=(3306,), open_loopback=(6379,)))
        self.assertIn("ports.database-open", found)
        self.assertNotIn("ports.review-loopback-only", found)

    def test_no_open_port_hits_nothing(self):
        self.assertEqual(self.ids(self.ports()), [])

    def test_loopback_rule_requires_both_lists(self):
        self.assertEqual(self.ids(self.ports(open_loopback=(6379,))),
                         ["ports.review-loopback-only"])




if __name__ == "__main__":
    unittest.main()