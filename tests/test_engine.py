import copy
import tempfile
import unittest
from unittest.mock import Mock

from phi_security.config import DEFAULT
from phi_security.engine import APIError, Engine
from phi_security.storage import Store
from tests.helpers import FakeCollector, fixture


class EngineWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

    def test_s3_uri_target_survives_report_filter(self):
        result = self.engine.scan({"resource": "s3://medical"})
        self.assertEqual([r["id"] for r in result["resources"]], ["r1"])

    def test_complete_rescan_resolves_fixed_configuration(self):
        self.collector.data["coverage"] = [{"service": "s3", "status": "COLLECTED"}]
        first = self.engine.scan({})
        old = next(f for f in first["findings"] if f["type"] == "PUBLIC_SENSITIVE_DATA")
        self.collector.data["resources"][0]["publicAccess"] = False
        report = self.engine.scan({})
        self.assertIn(old["id"], report["resolvedFindings"])
        self.assertEqual(self.engine.find("findings", old["id"])["status"], "RESOLVED")

    def test_partial_rescan_does_not_close_findings(self):
        first = self.engine.scan({})
        old = next(f for f in first["findings"] if f["type"] == "PUBLIC_SENSITIVE_DATA")
        self.collector.data["resources"][0]["publicAccess"] = False
        self.engine.scan({})
        self.assertEqual(self.engine.find("findings", old["id"])["status"], "OPEN")


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = {**DEFAULT, "db": self.tmp.name + "/test.db"}
        self.engine = Engine(self.config, FakeCollector(fixture()))

    def tearDown(self):
        self.engine.store.close()
        self.tmp.cleanup()

    def test_empty_inventory_is_not_demo(self):
        self.assertEqual(
            self.engine.dispatch("GET", "/inventory")["pagination"]["total"], 0
        )
        self.assertEqual(self.engine.dispatch("GET", "/health")["environment"], "live")

    def test_scan_is_partial_and_persisted(self):
        report = self.engine.scan({})
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["summary"]["total"], 2)
        self.assertTrue(
            any(f["type"] == "PUBLIC_SENSITIVE_DATA" for f in report["findings"])
        )
        self.assertEqual(
            len(self.engine.all("incidents")), 1
        )  # configuration alone does not create incident
        self.assertEqual(
            self.engine.all("baselines")[0]["status"], "INSUFFICIENT_HISTORY"
        )

    def test_repeat_scan_deduplicates(self):
        self.engine.scan({})
        n = len(self.engine.all("findings"))
        self.engine.scan({})
        self.assertEqual(len(self.engine.all("findings")), n)
        self.assertEqual(len(self.engine.all("evidence")), 3)

    def test_notes_persist_and_redact(self):
        self.engine.scan({})
        inc = self.engine.all("incidents")[0]
        self.engine.dispatch(
            "POST",
            "/incidents/" + inc["id"] + "/notes",
            {"note": "Contact patient@example.com"},
        )
        store = Store(self.config["db"])
        self.assertNotIn(
            "patient@example.com", store.get("incidents", inc["id"])["notes"][0]["text"]
        )
        store.close()
        self.engine.scan({})
        self.assertEqual(len(self.engine.find("incidents", inc["id"])["notes"]), 1)

    def test_investigation_is_retrievable(self):
        self.engine.scan({})
        result = self.engine.investigate({"resource": "medical"})
        inv = self.engine.dispatch("GET", "/investigate/" + result["investigationId"])
        self.assertEqual(inv["conclusion"]["assessment"], "insufficient_evidence")
        self.assertFalse(inv["conclusion"]["confirmedBreach"])

    def test_unknown_trigger_does_not_match_everything(self):
        self.engine.scan({})
        result = self.engine.investigate({"trigger": "anything"})
        self.assertEqual(
            self.engine.find("investigations", result["investigationId"])["evidence"],
            [],
        )

    def test_wrong_account_rejected(self):
        self.engine.scan({})
        self.engine.collector.data["account"] = "999999999999"
        with self.assertRaises(APIError):
            self.engine.scan({})
        self.assertEqual(self.engine.store.meta("account"), "123456789012")

    def test_routes_over_real_store(self):
        self.engine.scan({})
        routes = [
            "/inventory/summary",
            "/inventory/r1",
            "/findings",
            "/findings/summary",
            "/evidence",
            "/incidents",
            "/data-map",
            "/data-map/resource/r1",
            "/data-map/flow/p1/r1",
            "/iam/analysis",
            "/iam/principals",
            "/iam/principals/p1",
            "/iam/principals/p1/activity",
            "/iam/excessive-access",
            "/iam/decrypt-access",
            "/iam/cross-account",
            "/exposure",
            "/exposure/public",
            "/exposure/cross-account",
            "/exposure/third-party",
            "/logs/groups",
            "/logs/findings",
            "/logs/groups/app/findings",
            "/baselines",
            "/baselines/anomalies",
            "/baselines/p1",
            "/context",
        ]
        for route in routes:
            with self.subTest(route=route):
                self.assertIsInstance(self.engine.dispatch("GET", route), dict)

    def test_invalid_pagination(self):
        for params in [{"page": 0}, {"limit": -1}, {"page": "bad"}, {"limit": 1001}]:
            with self.assertRaises(APIError):
                self.engine.dispatch("GET", "/inventory", params)

    def test_lock_prevents_overlap(self):
        import time

        self.engine.store.db.execute(
            "INSERT INTO locks VALUES (?,?)", ("scan", time.time() + 100)
        )
        self.engine.store.commit()
        with self.assertRaises(APIError):
            self.engine.scan({})

    def test_scan_failure_releases_lock(self):
        self.engine.collector.collect = Mock(side_effect=RuntimeError("failure"))
        with self.assertRaises(RuntimeError):
            self.engine.scan({})
        self.assertEqual(
            self.engine.store.db.execute("SELECT count(*) FROM locks").fetchone()[0], 0
        )
