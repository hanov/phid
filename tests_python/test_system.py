import copy
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from phi_security.analysis import analyze, baseline, permissions
from phi_security.aws import AWS
from phi_security.collect import Collector
from phi_security.config import DEFAULT
from phi_security.engine import APIError, Engine
from phi_security.privacy import detect
from phi_security.storage import Store


class FakeCollector:
    def __init__(self, data):
        self.data = data

    def collect(self, *args):
        return copy.deepcopy(self.data)


def fixture():
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "account": "123456789012",
        "resources": [
            {
                "id": "r1",
                "arn": "arn:aws:s3:::medical",
                "name": "medical",
                "type": "S3",
                "region": "us-east-1",
                "account": "123456789012",
                "classification": "PHI_HIGH",
                "classificationBasis": "tag",
                "detectedTypes": ["MRN"],
                "encryption": {"type": "none"},
                "publicAccess": True,
                "riskLevel": "UNKNOWN",
                "tags": {},
                "evidence": ["e1"],
            },
            {
                "id": "l1",
                "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/app",
                "name": "/app",
                "type": "CloudWatchLogs",
                "region": "us-east-1",
                "classification": "PHI_HIGH",
                "classificationBasis": "log_pattern",
                "detectedTypes": ["MRN"],
                "encryption": {"type": "AWS_MANAGED"},
                "publicAccess": None,
                "riskLevel": "UNKNOWN",
                "tags": {},
                "evidence": ["e2"],
            },
        ],
        "principals": [
            {
                "id": "p1",
                "arn": "arn:aws:iam::123456789012:role/app",
                "name": "app",
                "type": "Role",
                "policies": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::medical/*",
                            }
                        ]
                    }
                ],
                "trustPolicy": {},
                "evidence": ["e3"],
            }
        ],
        "evidence": [
            {
                "id": "e1",
                "source": "configuration",
                "eventType": "ResourceObserved",
                "timestamp": timestamp,
                "resource": "arn:aws:s3:::medical",
            },
            {
                "id": "e2",
                "source": "cloudwatch",
                "eventType": "SensitiveLogEntry",
                "timestamp": timestamp,
                "resource": "arn:aws:logs:us-east-1:123456789012:log-group:/app",
                "resourceId": "l1",
                "classification": "PHI_HIGH",
                "detectedTypes": ["MRN"],
                "logGroup": "/app",
            },
            {
                "id": "e3",
                "source": "iam",
                "eventType": "PolicyObserved",
                "timestamp": timestamp,
            },
        ],
        "edges": [],
        "coverage": [{"service": "cloudtrail", "status": "AccessDenied"}],
        "eventsScanned": 1,
    }


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


class AWSTest(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.session = Mock()
        self.session.client.return_value = self.client
        self.aws = AWS({**DEFAULT, "max_resources": 100}, self.session)

    def test_allowlist_blocks_mutation_and_secret_retrieval(self):
        for service, op in [
            ("s3", "delete_object"),
            ("iam", "attach_role_policy"),
            ("secretsmanager", "get_secret_value"),
            ("kms", "decrypt"),
        ]:
            with self.assertRaises(PermissionError):
                self.aws.call(service, op, "us-east-1")
        self.session.client.assert_not_called()

    def test_object_read_requires_target_and_range(self):
        with self.assertRaises(PermissionError):
            self.aws.call("s3", "get_object", "us-east-1", Bucket="b", Key="k")
        self.aws.config.update(
            sample_objects=True, sample_keys=[{"bucket": "b", "key": "k"}]
        )
        with self.assertRaises(PermissionError):
            self.aws.call("s3", "get_object", "us-east-1", Bucket="b", Key="k")
        self.aws.call(
            "s3", "get_object", "us-east-1", Bucket="b", Key="k", Range="bytes=0-8191"
        )
        self.client.get_object.assert_called_once()

    def test_pagination(self):
        self.client.describe_db_instances.side_effect = [
            {"DBInstances": [{"id": 1}], "Marker": "next"},
            {"DBInstances": [{"id": 2}]},
        ]
        self.assertEqual(
            len(
                self.aws.pages(
                    "rds", "describe_db_instances", "us-east-1", "DBInstances"
                )
            ),
            2,
        )
        self.client.describe_db_instances.assert_called_with(Marker="next")

    def test_partial_errors_do_not_look_like_success(self):
        self.client.list_buckets.side_effect = Exception("credential-sensitive-text")
        self.assertIsNone(self.aws.call("s3", "list_buckets", "us-east-1"))
        self.assertNotIn("credential-sensitive-text", json.dumps(self.aws.coverage))
        self.assertNotEqual(self.aws.coverage[0]["status"], "COLLECTED")

    def test_truncation_is_visible(self):
        self.aws.config["max_pages"] = 1
        self.client.list_tables.return_value = {
            "TableNames": ["t1"],
            "LastEvaluatedTableName": "t1",
        }
        self.aws.pages("dynamodb", "list_tables", "us-east-1", "TableNames")
        self.assertEqual(self.aws.coverage[-1]["status"], "TRUNCATED")


class AnalysisTest(unittest.TestCase):
    def test_sensitive_patterns(self):
        for text, value in [
            ("MRN: 883122", "883122"),
            ("Authorization: Bearer secret", "secret"),
            ("patient@example.com", "patient@example.com"),
            ("DOB: 01/02/1980", "01/02/1980"),
        ]:
            self.assertNotIn(value, detect(text)["redacted"])

    def test_policy_is_candidate_not_effective(self):
        data = fixture()
        p = permissions(data["principals"][0], data["resources"], DEFAULT)
        self.assertEqual(p["candidateResources"], ["r1"])
        self.assertIn("candidate", p["accessAssessment"])
        self.assertFalse(p["hasExcessiveAccess"])

    def test_name_alone_does_not_make_incident(self):
        data = fixture()
        findings, incidents, _ = analyze(
            data["resources"][:1], [], data["evidence"], DEFAULT
        )
        self.assertTrue(findings)
        self.assertEqual(incidents, [])

    def test_baseline_excludes_current_window(self):
        p = fixture()["principals"][0]
        at = datetime.now(timezone.utc)
        events = []
        for day in range(2, 10):
            events.append(
                {
                    "id": "old" + str(day),
                    "identity": p["arn"],
                    "source": "cloudtrail",
                    "successful": True,
                    "eventType": "GetObject",
                    "timestamp": (at - timedelta(days=day)).isoformat(),
                }
            )
        for i in range(10):
            events.append(
                {
                    "id": str(i),
                    "identity": p["arn"],
                    "source": "cloudtrail",
                    "successful": True,
                    "eventType": "GetObject",
                    "timestamp": at.isoformat(),
                }
            )
        b = baseline(events, [p], {**DEFAULT, "bulk_threshold": 5}, at)[0]
        self.assertEqual(b["dailyMean"], 1)
        self.assertEqual(b["currentCount"], 10)
        self.assertEqual(b["status"], "ANOMALY")

    def test_log_collector_does_not_persist_raw_message(self):
        aws = Mock()
        aws.pages.side_effect = [
            [{"logGroupName": "/app", "arn": "arn:logs"}],
            [{"eventId": "e", "timestamp": 1, "message": "patient@example.com"}],
        ]
        c = Collector(DEFAULT, aws)
        c.account = "123"
        c.logs("us-east-1")
        self.assertNotIn("patient@example.com", json.dumps(c.evidence))
        self.assertEqual(c.evidence[-1]["detectedTypes"], ["EMAIL"])


class PrivacyPatternTest(unittest.TestCase):
    def test_expanded_secret_keywords(self):
        cases = [
            ("client_secret: abc123xyz", "abc123xyz"),
            ("api_secret=my-api-key-value", "my-api-key-value"),
            ("refresh_token: the-token-value", "the-token-value"),
            ("private_key=-----BEGIN-KEY", "-----BEGIN-KEY"),
            ("passwd: hunter2", "hunter2"),
        ]
        for text, value in cases:
            with self.subTest(text=text):
                result = detect(text)
                self.assertEqual(
                    result["classification"],
                    "CREDENTIAL",
                    msg=f"Expected CREDENTIAL for: {text}",
                )
                self.assertNotIn(
                    value,
                    result["redacted"],
                    msg=f"Value should be redacted in: {text}",
                )

    def test_health_plan_id_detected_and_classified(self):
        for text in [
            "member_id: XYZ12345",
            "policy_number: AB1234",
            "subscriber_id: GRP001",
            "group_no: 9876",
        ]:
            with self.subTest(text=text):
                result = detect(text)
                self.assertIn(
                    "HEALTH_PLAN_ID",
                    result["detectedTypes"],
                    msg=f"No HEALTH_PLAN_ID in: {text}",
                )
                self.assertEqual(
                    result["classification"],
                    "PHI_HIGH",
                    msg=f"Expected PHI_HIGH for: {text}",
                )

    def test_npi_detected_and_classified(self):
        result = detect("NPI: 1234567890")
        self.assertIn("NPI", result["detectedTypes"])
        self.assertIn(result["classification"], ["PHI", "PHI_HIGH"])

    def test_npi_requires_10_digits(self):
        result = detect("NPI: 12345")  # too short
        self.assertNotIn("NPI", result["detectedTypes"])


class RiskScoringTest(unittest.TestCase):
    def _resource(self, classification, public=False, encrypted=True):
        return {
            "id": "r-" + classification,
            "arn": "arn:test:" + classification,
            "classification": classification,
            "publicAccess": bool(public),
            "encryption": {"type": "SSE-KMS" if encrypted else "none"},
        }

    def test_phi_high_scores_higher_than_pii(self):
        from phi_security.analysis import compute_risk_score

        phi_high = self._resource("PHI_HIGH")
        pii = self._resource("PII")
        self.assertGreater(
            compute_risk_score(phi_high, [], [], {})["score"],
            compute_risk_score(pii, [], [], {})["score"],
        )

    def test_public_exposure_increases_score(self):
        from phi_security.analysis import compute_risk_score

        private = self._resource("PHI")
        public = self._resource("PHI", public=True)
        self.assertGreater(
            compute_risk_score(public, [], [], {})["score"],
            compute_risk_score(private, [], [], {})["score"],
        )

    def test_unencrypted_increases_score(self):
        from phi_security.analysis import compute_risk_score

        enc = self._resource("PHI")
        plain = self._resource("PHI", encrypted=False)
        self.assertGreater(
            compute_risk_score(plain, [], [], {})["score"],
            compute_risk_score(enc, [], [], {})["score"],
        )

    def test_score_bounded_0_to_100(self):
        from phi_security.analysis import compute_risk_score

        worst = self._resource("PHI_HIGH", public=True, encrypted=False)
        result = compute_risk_score(worst, [], [], {})
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_factors_list_populated_for_sensitive_resource(self):
        from phi_security.analysis import compute_risk_score

        r = self._resource("PHI_HIGH", public=True, encrypted=False)
        result = compute_risk_score(r, [], [], {})
        factor_names = [f["factor"] for f in result["factors"]]
        self.assertIn("data_sensitivity", factor_names)
        self.assertIn("public_exposure", factor_names)
        self.assertIn("unencrypted", factor_names)

    def test_level_string_reflects_score(self):
        from phi_security.analysis import compute_risk_score

        r = self._resource("PHI_HIGH", public=True, encrypted=False)
        result = compute_risk_score(r, [], [], {})
        self.assertIn(result["level"], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    def test_unclassified_resource_has_zero_sensitivity_contribution(self):
        from phi_security.analysis import compute_risk_score

        r = self._resource("UNCLASSIFIED")
        result = compute_risk_score(r, [], [], {})
        self.assertFalse(
            any(f["factor"] == "data_sensitivity" for f in result["factors"])
        )

    def test_scan_attaches_risk_score_to_resources(self):
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        config = {**DEFAULT, "db": tmp.name + "/test.db"}
        engine = Engine(config, FakeCollector(fixture()))
        report = engine.scan({})
        engine.store.close()
        tmp.cleanup()
        for r in report["resources"]:
            self.assertIn("riskScore", r, msg=f"riskScore missing from {r['id']}")
            self.assertIn("score", r["riskScore"])
            self.assertIn("level", r["riskScore"])


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


if __name__ == "__main__":
    unittest.main()


class CorrelationTest(unittest.TestCase):
    def test_egress_alone_never_means_exfiltration(self):
        from phi_security.correlation import correlate

        data = fixture()
        flow = {
            "id": "flow",
            "source": "vpc-flow",
            "eventType": "NetworkFlow",
            "sourceIp": "10.0.0.1",
            "destinationIp": "8.8.8.8",
            "bytes": 10000000,
            "action": "ACCEPT",
            "logStatus": "OK",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.assertEqual(correlate(data["resources"], [flow], DEFAULT), [])

    def test_multiple_signals_are_required_for_possible_exfiltration(self):
        from phi_security.correlation import correlate

        data = fixture()
        at = datetime.now(timezone.utc).isoformat()
        identity = data["principals"][0]["arn"]
        events = [
            {
                "id": "read" + str(i),
                "source": "cloudtrail",
                "eventType": "GetObject",
                "resource": data["resources"][0]["arn"],
                "identity": identity,
                "successful": True,
                "sourceIp": "10.0.0.1",
                "timestamp": at,
            }
            for i in range(5)
        ]
        config = {**DEFAULT, "bulk_threshold": 5}
        self.assertEqual(
            correlate(data["resources"], events, config)[0]["assessment"],
            "confirmed_access",
        )
        events.append(
            {
                "id": "decrypt",
                "source": "cloudtrail",
                "eventType": "Decrypt",
                "identity": identity,
                "successful": True,
                "timestamp": at,
            }
        )
        events.append(
            {
                "id": "flow",
                "source": "vpc-flow",
                "eventType": "NetworkFlow",
                "sourceIp": "10.0.0.1",
                "destinationIp": "8.8.8.8",
                "bytes": 10000000,
                "action": "ACCEPT",
                "logStatus": "OK",
                "timestamp": at,
            }
        )
        result = correlate(data["resources"], events, config)[0]
        self.assertEqual(result["assessment"], "possible_exfiltration")
        self.assertIn("decrypt", result["evidence"])
        self.assertIn("flow", result["evidence"])
        self.assertEqual(
            correlate(
                data["resources"], events, {**config, "approved_cidrs": ["8.8.8.0/24"]}
            )[0]["assessment"],
            "confirmed_access",
        )

    def test_remote_llm_disabled_by_default(self):
        from unittest.mock import patch

        from phi_security.llm import Router

        with patch.dict(os.environ, {}, clear=True), self.assertRaises(PermissionError):
            Router({"llm": {"provider": "bedrock"}}).query("summarize", {})
