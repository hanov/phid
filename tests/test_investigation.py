import copy
import tempfile
import unittest

from phi_security.config import DEFAULT
from phi_security.engine import Engine
from tests.helpers import FakeCollector, fixture


class InvestigationWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

    def test_trigger_investigation_uses_finding_evidence(self):
        result = self.engine.scan({})
        finding = next(
            f for f in result["findings"] if f["type"] == "SENSITIVE_DATA_IN_LOGS"
        )
        review = self.engine.investigate({"trigger": finding["id"], "refresh": False})
        stored = self.engine.find("investigations", review["investigationId"])
        self.assertIn("e2", stored["evidence"])
        self.assertIn("counter_evidence", [s["query"] for s in stored["steps"]])
        self.assertIn("evidenceQuality", stored)


class InvestigationHypothesisTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = {**DEFAULT, "db": self.tmp.name + "/test.db", "bulk_threshold": 5}
        self.engine = Engine(self.config, FakeCollector(fixture()))
        self.engine.scan({})
        self.identity = fixture()["principals"][0]["arn"]

    def tearDown(self):
        self.engine.store.close()
        self.tmp.cleanup()

    def _add_reads(self, n, source_ip=None, destination_account=None):
        from datetime import datetime, timezone

        at = datetime.now(timezone.utc).isoformat()
        for i in range(n):
            ev = {
                "id": f"tr{i}",
                "source": "cloudtrail",
                "eventType": "GetObject",
                "resource": "arn:aws:s3:::medical/f.txt",
                "identity": self.identity,
                "successful": True,
                "timestamp": at,
            }
            if source_ip:
                ev["sourceIp"] = source_ip
            if destination_account:
                ev["destinationAccount"] = destination_account
            self.engine.store.put("evidence", ev)
        self.engine.store.commit()

    def test_bulk_reads_trigger_bulk_hypothesis(self):
        self._add_reads(6)  # exceeds bulk_threshold=5
        result = self.engine.investigate({"resource": "medical", "refresh": False})
        inv = self.engine.find("investigations", result["investigationId"])
        ids = [h["id"] for h in inv["hypotheses"]]
        self.assertIn("bulk_reads", ids)

    def test_unexpected_public_ip_triggers_ip_hypothesis(self):
        # approved_cidrs is empty by default, so any global IP is unexpected.
        self._add_reads(1, source_ip="8.8.8.8")
        result = self.engine.investigate({"resource": "medical", "refresh": False})
        inv = self.engine.find("investigations", result["investigationId"])
        ids = [h["id"] for h in inv["hypotheses"]]
        self.assertIn("unexpected_ip", ids)

    def test_private_ip_does_not_trigger_ip_hypothesis(self):
        self._add_reads(1, source_ip="10.0.0.1")
        result = self.engine.investigate({"resource": "medical", "refresh": False})
        inv = self.engine.find("investigations", result["investigationId"])
        ids = [h["id"] for h in inv["hypotheses"]]
        self.assertNotIn("unexpected_ip", ids)

    def test_cross_account_triggers_cross_account_hypothesis(self):
        self._add_reads(1, destination_account="999999999999")
        result = self.engine.investigate({"resource": "medical", "refresh": False})
        inv = self.engine.find("investigations", result["investigationId"])
        ids = [h["id"] for h in inv["hypotheses"]]
        self.assertIn("cross_account", ids)

    def test_no_signals_falls_back_to_generic_hypothesis(self):
        # No extra events — only e1 (ResourceObserved, not a CloudTrail read).
        result = self.engine.investigate({"resource": "medical", "refresh": False})
        inv = self.engine.find("investigations", result["investigationId"])
        ids = [h["id"] for h in inv["hypotheses"]]
        self.assertEqual(ids, ["unexpected_access"])

    def test_approved_cidr_suppresses_ip_hypothesis(self):
        self.engine.config["approved_cidrs"] = ["8.8.8.0/24"]
        self._add_reads(1, source_ip="8.8.8.8")
        result = self.engine.investigate({"resource": "medical", "refresh": False})
        inv = self.engine.find("investigations", result["investigationId"])
        ids = [h["id"] for h in inv["hypotheses"]]
        self.assertNotIn("unexpected_ip", ids)
