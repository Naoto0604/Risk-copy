import unittest
from pathlib import Path

from engine.observations import Observation
from engine.rule_runner import run
from engine.rules import load_rules_from_dir

HOST = "example.test"

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "ports"

SATISFIED = frozenset({"proof", "consent"})


def observation(*open_ports):
    return Observation.ok(
        "ports", HOST,
        {
            "host": HOST,
            "ports": [],
            "open": list(open_ports),
            "open_external": list(open_ports),
            "open_loopback": [],
            "scope_counts": {"PUBLIC": len(open_ports)} if open_ports else {},
            "counts": {"open": len(open_ports)},
            "tried": len(open_ports),
            "truncated": False,
            "truncated_reason": None,
        },
    )

def ids_of(findings):
    return {finding.rule_id for finding in findings}


def run_with(observations, satisfied=SATISFIED):
    return run(load_rules_from_dir(RULES_DIR), observations, satisfied=satisfied)


class TestLoading(unittest.TestCase):

    def test_directory_loads(self):
        self.assertGreaterEqual(len(load_rules_from_dir(RULES_DIR)), 5)


class TestDatabases(unittest.TestCase):

    def test_mongodb_is_reported(self):
        _normal, low = run_with([observation(27017)])
        self.assertIn("ports.mongodb-open", ids_of(low))

    def test_redis_is_reported(self):
        _normal, low = run_with([observation(6379)])
        self.assertIn("ports.redis-open", ids_of(low))

    def test_mysql_is_reported(self):
        _normal, low = run_with([observation(3306)])
        self.assertIn("ports.database-open", ids_of(low))

    def test_postgres_is_reported(self):
        _normal, low = run_with([observation(5432)])
        self.assertIn("ports.database-open", ids_of(low))

    def test_mssql_is_reported(self):
        _normal, low = run_with([observation(1433)])
        self.assertIn("ports.database-open", ids_of(low))


class TestManagement(unittest.TestCase):

    def test_rdp_is_reported(self):
        _normal, low = run_with([observation(3389)])
        self.assertIn("ports.rdp-open", ids_of(low))

    def test_dev_server_is_reported(self):
        _normal, low = run_with([observation(8000)])
        self.assertIn("ports.dev-server-open", ids_of(low))


class TestQuiet(unittest.TestCase):

    def test_only_web_ports_is_not_reported(self):
        normal, low = run_with([observation(80, 443)])
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_closed_ports_do_not_fire(self):
        normal, low = run_with([observation()])
        self.assertEqual(normal, [])
        self.assertEqual(low, [])


class TestGate(unittest.TestCase):

    def test_no_findings_without_requirements(self):
        normal, low = run_with([observation(6379)], satisfied=frozenset())
        self.assertEqual(normal, [])
        self.assertEqual(low, [])

    def test_subject_is_the_host(self):
        _normal, low = run_with([observation(6379)])
        self.assertTrue(all(finding.subject == HOST for finding in low))


if __name__ == "__main__":
    unittest.main()