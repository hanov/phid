"""Behavioral acceptance tests for the Python requirement implementation."""

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from test_system import FakeCollector, fixture

from phi_security.agent import triage
from phi_security.analysis import permissions
from phi_security.aws import AWS
from phi_security.behavior import detect as behavior
from phi_security.collect import Collector
from phi_security.config import DEFAULT, load, normalize
from phi_security.controls import assess
from phi_security.discovery import config_history, database_samples, objects
from phi_security.engine import Engine
from phi_security.llm import Router
from phi_security.privacy import detect, merge_classification
from phi_security.questions import ask


class RequirementsTest(unittest.TestCase):
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

    def test_cloudtrail_one_event_one_count(self):
        collector = Collector(self.config, Mock())
        collector.cloudtrail_event(
            {
                "eventID": "event1",
                "eventName": "GetObject",
                "eventTime": "2026-09-29T00:00:00Z",
                "userIdentity": {"arn": "identity"},
                "resources": [{"ARN": "arn:aws:s3:::medical/a/b"}],
                "requestParameters": {"bucketName": "medical", "key": "a/b"},
            },
            "us-east-1",
        )
        self.assertEqual(len(collector.evidence), 1)
        self.assertEqual(collector.evidence[0]["sourceEventId"], "event1")
        self.assertEqual(collector.evidence[0]["objectPrefix"], "a")
        self.assertEqual(collector.evidence[0]["resource"], "arn:aws:s3:::medical/a/b")

    def test_classification_never_downgrades(self):
        r = {
            "classification": "PHI_HIGH",
            "classificationBasis": "sample_pattern",
            "detectedTypes": ["MRN"],
        }
        merge_classification(r, "PII", ["EMAIL"], "log_pattern", self.config)
        self.assertEqual(r["classification"], "PHI_HIGH")
        self.assertEqual(r["detectedTypes"], ["EMAIL", "MRN"])

    def test_custom_mapping_and_sensitivity(self):
        result = detect(
            "ACCT-123456",
            [
                {
                    "name": "ORG_ACCOUNT",
                    "regex": r"ACCT-\d+",
                    "classification": "ORG_PRIVATE",
                }
            ],
        )
        self.assertEqual(result["classification"], "ORG_PRIVATE")
        r = {"classification": "PUBLIC"}
        config = {
            **self.config,
            "classification_taxonomy": {
                "ORG_PRIVATE": {"sensitive": True, "sensitivity": 40}
            },
        }
        merge_classification(
            r, result["classification"], result["detectedTypes"], "sample", config
        )
        self.assertTrue(r["isSensitive"])
        self.assertEqual(r["sensitivityScore"], 40)

    def test_json_schema_values_are_not_returned(self):
        result = detect('{"patientName":"jane doe","diagnosis":"asthma"}')
        self.assertIn("PATIENT_NAME", result["detectedTypes"])
        self.assertEqual(result["classification"], "PHI_HIGH")
        self.assertNotIn("jane", result["redacted"])
        self.assertNotIn("asthma", result["redacted"])

    def test_entropy_secret(self):
        token = "abCDeF0123456789+/xyZXYzy98zyABcd123456"
        result = detect(token)
        self.assertIn("HIGH_ENTROPY_SECRET", result["detectedTypes"])
        self.assertNotIn(token, result["redacted"])

    def test_service_mismatch_does_not_imply_access(self):
        principal = fixture()["principals"][0]
        principal["policies"] = [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}
                ]
            }
        ]
        p = permissions(principal, fixture()["resources"], self.config)
        self.assertEqual(p["candidateResources"], [])

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

    def test_agent_does_not_repeat_same_evidence_review(self):
        report = self.engine.scan({})
        first = triage(self.engine, report)
        second = triage(self.engine, report)
        self.assertTrue(first)
        self.assertEqual(second, [])

    def test_natural_language_log_query(self):
        self.engine.scan({})
        result = ask(self.engine, "Was PHI written into logs today?", {})
        self.assertEqual(result["intent"], "log_leakage")
        self.assertEqual(len(result["records"]), 1)
        self.assertIn("from", result["timeRange"])

    def test_natural_language_no_evidence_does_not_assert_exfiltration(self):
        result = ask(self.engine, "Did PHI leave the production VPC?", {})
        self.assertEqual(result["records"], [])
        self.assertIn("do not prove", result["answer"])

    def test_controls_unknown_not_passed(self):
        resources = fixture()["resources"]
        controls = assess(resources, [], [])
        self.assertGreater(controls["summary"]["UNKNOWN"], 0)
        self.assertIn("No legal", controls["assessment"])

    def test_config_is_deep_copied(self):
        with patch.dict("os.environ", {}, clear=True):
            a = load(db_path=self.config["db"])
            a["llm"]["models"]["fast"] = "test"
            b = load(db_path=self.config["db"])
        self.assertNotIn("fast", b["llm"]["models"])

    def test_nested_config(self):
        values = normalize(
            {
                "aws": {"profile": "prod", "regions": ["us-west-2"]},
                "storage": {"path": "x.db"},
                "detection": {"log_phi_detection": False},
            }
        )
        self.assertEqual(values["profile"], "prod")
        self.assertEqual(values["db"], "x.db")
        self.assertFalse(values["detectors"]["log_phi_detection"])

    def test_reject_remote_provider(self):
        path = Path(self.tmp.name) / "remote.json"
        path.write_text(json.dumps({"llm": {"provider": "bedrock"}}))
        with self.assertRaises(ValueError):
            load(str(path), self.config["db"])


class LocalModelTest(unittest.TestCase):
    def setUp(self):
        self.config = {
            "llm": {
                "provider": "ollama",
                "models": {"reasoning": "local-model"},
                "base_url": "http://127.0.0.1:11434",
            }
        }
        self.context = [
            {
                "id": "e1",
                "source": "cloudtrail",
                "eventType": "GetObject",
                "rawMessage": "patient secret",
            }
        ]

    def response(self, value):
        response = Mock()
        response.read.return_value = json.dumps(
            {"message": {"content": json.dumps(value)}}
        ).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def test_loopback_inference_redacts_and_validates_refs(self):
        opener = Mock()
        opener.open.return_value = self.response(
            {"summary": "Observed read.", "evidenceIds": ["e1"]}
        )
        with patch("phi_security.llm.build_opener", return_value=opener):
            result = Router(self.config).query("Review this", self.context)
        self.assertTrue(result["advisory"])
        self.assertFalse(result["verifiedConclusion"])
        sent = json.loads(opener.open.call_args.args[0].data)
        self.assertNotIn("patient secret", str(sent))
        self.assertFalse(sent["stream"])

    def test_unknown_evidence_rejected(self):
        opener = Mock()
        opener.open.return_value = self.response(
            {"summary": "Invented", "evidenceIds": ["fake"]}
        )
        with (
            patch("phi_security.llm.build_opener", return_value=opener),
            self.assertRaises(ValueError),
        ):
            Router(self.config).query("Review", self.context)

    def test_remote_ollama_and_credentials_rejected_before_network(self):
        for url in [
            "http://example.com",
            "http://127.0.0.1:11434/evil",
            "http://user:secret@localhost:11434",
        ]:
            self.config["llm"]["base_url"] = url
            with (
                patch("phi_security.llm.build_opener") as network,
                self.assertRaises(ValueError),
            ):
                Router(self.config).query("Review", self.context)
            network.assert_not_called()


class BehaviorTest(unittest.TestCase):
    def setUp(self):
        self.at = datetime.now(timezone.utc)
        self.config = {**copy.deepcopy(DEFAULT), "min_baseline_days": 3}
        self.resources = fixture()["resources"][:1]
        self.arn = self.resources[0]["arn"]
        self.events = [
            self.event(str(day), self.at - timedelta(days=day), "old-role", "10.0.0.1")
            for day in range(2, 7)
        ]

    def event(self, identifier, time, identity, ip):
        return {
            "id": identifier,
            "source": "cloudtrail",
            "eventType": "GetObject",
            "resource": self.arn,
            "timestamp": time.isoformat(),
            "identity": identity,
            "sourceIp": ip,
            "region": "us-east-1",
            "successful": True,
        }

    def test_single_novel_identity_not_alerted(self):
        self.events.append(self.event("new", self.at, "new-role", "10.0.0.1"))
        result = behavior(self.resources, self.events, [], self.config, self.at)
        self.assertFalse(
            any(f["type"] == "UNEXPECTED_SENSITIVE_ACCESS" for f in result)
        )

    def test_new_ip_plus_off_hours_alert(self):
        self.events.append(self.event("new", self.at, "old-role", "8.8.8.8"))
        self.config["expected_hours"] = {"old-role": [(self.at.hour + 1) % 24]}
        result = behavior(self.resources, self.events, [], self.config, self.at)
        self.assertTrue(any(f["type"] == "UNEXPECTED_SENSITIVE_ACCESS" for f in result))

    def test_approved_activity_suppresses_behavior(self):
        self.events.append(self.event("new", self.at, "old-role", "8.8.8.8"))
        self.config["expected_hours"] = {"old-role": [(self.at.hour + 1) % 24]}
        self.config["approved_activity"] = [
            {
                "identity": "old-role",
                "resource": self.arn,
                "from": (self.at - timedelta(hours=1)).isoformat(),
                "to": (self.at + timedelta(hours=1)).isoformat(),
                "reason": "Approved migration",
            }
        ]
        result = behavior(self.resources, self.events, [], self.config, self.at)
        self.assertFalse(
            any(f["type"] == "UNEXPECTED_SENSITIVE_ACCESS" for f in result)
        )


class DiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(DEFAULT)
        self.aws = Mock()
        self.collector = Collector(self.config, self.aws)
        self.collector.account = "123456789012"

    def test_sampling_requires_explicit_table_and_bounded_limit(self):
        aws = AWS(self.config, Mock())
        with self.assertRaises(PermissionError):
            aws.call("dynamodb", "scan", "us-east-1", TableName="patients", Limit=5)
        self.config["db_samples"] = [
            {
                "service": "dynamodb",
                "table": "patients",
                "region": "us-east-1",
                "limit": 5,
            }
        ]
        aws.call("dynamodb", "scan", "us-east-1", TableName="patients", Limit=5)
        with self.assertRaises(PermissionError):
            aws.call("dynamodb", "scan", "us-east-1", TableName="patients", Limit=500)

    def test_database_sample_does_not_persist_raw_data(self):
        self.config["db_samples"] = [
            {"service": "dynamodb", "table": "patients", "region": "us-east-1"}
        ]
        self.collector.asset(
            "DynamoDB",
            "patients",
            "arn:aws:dynamodb:us-east-1:123456789012:table/patients",
            "us-east-1",
        )
        self.aws.call.return_value = {
            "Items": [{"patient_name": {"S": "Alice Test"}, "mrn": {"S": "12345"}}]
        }
        database_samples(self.collector, "us-east-1")
        self.assertNotIn("Alice Test", json.dumps(self.collector.evidence))
        self.assertEqual(self.collector.resources[0]["classification"], "PHI_HIGH")

    def test_object_metadata_opt_in(self):
        r = fixture()["resources"][0]
        objects(self.collector, r)
        self.aws.pages.assert_not_called()
        self.config["object_metadata"] = True
        self.aws.pages.return_value = [{"Key": "prefix/a", "Size": 42}]
        objects(self.collector, r)
        self.assertEqual(self.collector.evidence[0]["objectPrefix"], "prefix")

    def test_config_history_stores_changes_not_raw_configuration(self):
        self.config["config_history"] = True
        self.aws.pages.return_value = [
            {
                "configuration": '{"secret":"never-store","public":false}',
                "configurationStateId": "1",
                "configurationItemCaptureTime": "2026-09-01T00:00:00Z",
            },
            {
                "configuration": '{"secret":"never-store","public":true}',
                "configurationStateId": "2",
                "configurationItemCaptureTime": "2026-09-02T00:00:00Z",
            },
        ]
        config_history(
            self.collector,
            "us-east-1",
            {"resourceId": "r", "resourceType": "AWS::S3::Bucket", "arn": "arn:test"},
        )
        self.assertNotIn("never-store", json.dumps(self.collector.evidence))
        self.assertEqual(self.collector.evidence[-1]["changedFields"], ["public"])
