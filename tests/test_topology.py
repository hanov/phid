import copy
import unittest
from unittest.mock import Mock

from phi_security.collect import Collector
from phi_security.config import DEFAULT
from phi_security.topology import dot, enrich


class TopologyBoundaryTest(unittest.TestCase):
    def test_dot_escapes_untrusted_labels(self):
        result = dot(
            {"nodes": [{"id": "x", "label": '"; malicious -> node'}], "edges": []}
        )
        self.assertIn('\\"; malicious', result)
        self.assertTrue(result.startswith("digraph"))

    def test_backup_inherits_source_classification_and_evidence_edge(self):
        collector = Collector(copy.deepcopy(DEFAULT), Mock())
        collector.account = "123456789012"
        source = collector.asset(
            "RDS",
            "db",
            "arn:aws:rds:us-east-1:123456789012:db:db",
            "us-east-1",
            {"classification": "PHI_HIGH"},
        )
        backup = collector.asset(
            "RDSSnapshot",
            "snapshot",
            "arn:aws:rds:us-east-1:123456789012:snapshot:snapshot",
            "us-east-1",
            sourceResource="db",
        )
        enrich(collector)
        self.assertEqual(backup["classification"], "PHI_HIGH")
        self.assertTrue(
            any(
                e["from"] == source["arn"] and e["to"] == backup["arn"]
                for e in collector.edges
            )
        )
