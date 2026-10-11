import copy
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from phi_security.analysis import permissions
from phi_security.aws import ALLOW
from phi_security.collect import Collector
from phi_security.config import DEFAULT, load
from phi_security.database import postgres_samples
from phi_security.discovery import metrics
from phi_security.events import unique_events
from phi_security.llm import NoRedirect, Router
from phi_security.topology import dot, enrich


class SafetyAndWorkflowTest(unittest.TestCase):
    def test_legacy_cloudtrail_rows_deduplicate_preserving_resources(self):
        event = "12345678-abcd-abcd-abcd-123456789012"
        rows = [
            {
                "id": "a",
                "source": "cloudtrail",
                "reference": event + "arn:aws:s3:::b",
                "resource": "arn:aws:s3:::b",
            },
            {
                "id": "b",
                "source": "cloudtrail",
                "reference": event + "arn:aws:s3:::b/key",
                "resource": "arn:aws:s3:::b/key",
            },
            {
                "id": "c",
                "source": "cloudtrail",
                "sourceEventId": event,
                "resource": "arn:aws:s3:::b/key",
            },
        ]
        result = unique_events(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]["resources"]), 2)

    def test_explicit_deny_blocks_broad_read_candidate(self):
        p = {
            "arn": "arn:aws:iam::123456789012:role/test",
            "policies": [
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                        {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"},
                    ]
                }
            ],
        }
        resource = {"id": "r", "arn": "arn:aws:s3:::patients", "classification": "PHI"}
        result = permissions(p, [resource], DEFAULT)
        self.assertEqual(result["candidateResources"], [])

    def test_arn_resources_match_case_sensitively(self):
        p = {
            "arn": "arn:aws:iam::123456789012:role/test",
            "policies": [
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "dynamodb:Scan",
                            "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Patients",
                        }
                    ]
                }
            ],
        }
        resource = {
            "id": "r",
            "arn": "arn:aws:dynamodb:us-east-1:123456789012:table/patients",
            "classification": "PHI",
        }
        self.assertEqual(permissions(p, [resource], DEFAULT)["candidateResources"], [])

    def test_redirects_are_blocked(self):
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(
                None, None, None, None, None, "http://external"
            )

    def test_api_allowlist_contains_no_mutations_or_secrets(self):
        for service, operations in ALLOW.items():
            for operation in operations:
                self.assertFalse(
                    operation.startswith(
                        (
                            "put_",
                            "update_",
                            "delete_",
                            "create_",
                            "modify_",
                            "attach_",
                            "detach_",
                            "stop_",
                            "terminate_",
                            "revoke_",
                            "authorize_",
                        )
                    ),
                    (service, operation),
                )
                self.assertNotEqual(operation, "get_secret_value")

    def test_sql_sample_injection_rejected_before_connect(self):
        collector = Collector(
            {
                **copy.deepcopy(DEFAULT),
                "db_samples": [
                    {
                        "service": "postgresql",
                        "region": "us-east-1",
                        "table": "patients; DROP TABLE users",
                    }
                ],
            },
            Mock(),
        )
        with self.assertRaises(ValueError):
            postgres_samples(collector, "us-east-1")

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

    def test_multi_service_metrics_have_coverage_for_empty_data(self):
        aws = Mock()
        aws.call.return_value = {"Datapoints": []}
        aws.coverage = []
        collector = Collector(copy.deepcopy(DEFAULT), aws)
        collector.account = "123456789012"
        collector.asset(
            "Lambda",
            "fn",
            "arn:aws:lambda:us-east-1:123456789012:function:fn",
            "us-east-1",
        )
        collector.asset(
            "DynamoDB",
            "table",
            "arn:aws:dynamodb:us-east-1:123456789012:table/table",
            "us-east-1",
        )
        metrics(collector, "us-east-1")
        names = {call.kwargs["MetricName"] for call in aws.call.call_args_list}
        self.assertEqual(names, {"Invocations", "ConsumedReadCapacityUnits"})
        self.assertEqual(len(aws.coverage), 2)

    def test_bad_config_and_remote_provider_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for value in [
                {"llm": {"provider": "remote"}},
                {
                    "db_samples": [
                        {
                            "service": "dynamodb",
                            "table": "t",
                            "region": "us-east-1",
                            "limit": 11,
                        }
                    ]
                },
                {"custom_patterns": [{"name": "bad", "regex": "["}]},
                {"regions": ["not-a-region"]},
            ]:
                path.write_text(json.dumps(value))
                with (
                    patch.dict(os.environ, {}, clear=True),
                    self.assertRaises((ValueError, __import__("re").error)),
                ):
                    load(str(path))

    def test_yaml_nested_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                "aws:\n  regions: [us-west-2]\n  profile: prod\nstorage:\n  path: local.db\nllm:\n  provider: none\n"
            )
            with patch.dict(os.environ, {}, clear=True):
                result = load(str(path))
            self.assertEqual(result["regions"], ["us-west-2"])
            self.assertEqual(result["db"], "local.db")

    def test_approved_bulk_window_not_reported_as_exfiltration(self):
        from phi_security.correlation import correlate

        at = datetime.now(timezone.utc)
        arn = "arn:aws:s3:::patients"
        resource = {"id": "r", "arn": arn, "classification": "PHI"}
        events = [
            {
                "id": str(i),
                "source": "cloudtrail",
                "eventType": "GetObject",
                "timestamp": at.isoformat(),
                "resource": arn,
                "identity": "role",
                "successful": True,
            }
            for i in range(5)
        ]
        config = {
            **DEFAULT,
            "bulk_threshold": 5,
            "approved_activity": [
                {
                    "identity": "role",
                    "resource": arn,
                    "from": (at - timedelta(hours=1)).isoformat(),
                    "to": (at + timedelta(hours=1)).isoformat(),
                }
            ],
        }
        self.assertEqual(correlate([resource], events, config), [])

    def test_model_raw_data_is_not_in_context(self):
        from phi_security.llm import minimized_context

        rows = minimized_context(
            [
                {
                    "id": "e",
                    "message": "raw patient record",
                    "password": "secret",
                    "title": "Contact patient@example.com",
                }
            ],
            1,
        )
        self.assertNotIn("raw patient record", str(rows))
        self.assertNotIn("patient@example.com", str(rows))
        self.assertNotIn("password", rows[0])

    def test_baseline_duplicate_ids_do_not_inflate_count(self):
        from phi_security.analysis import baseline

        at = datetime.now(timezone.utc)
        events = [
            {
                "id": str(i),
                "sourceEventId": "same",
                "source": "cloudtrail",
                "identity": "role",
                "eventType": "GetObject",
                "successful": True,
                "timestamp": at.isoformat(),
            }
            for i in range(2)
        ]
        result = baseline(
            events, [{"id": "p", "arn": "role", "name": "role"}], DEFAULT, at
        )
        self.assertEqual(result[0]["currentCount"], 1)

    def test_collector_parameters_match_installed_botocore_models(self):
        import botocore.session
        from botocore.validate import validate_parameters

        from phi_security.network import collect as network

        session = botocore.session.get_session()
        calls = []

        class ValidatingAWS:
            coverage: list = []  # noqa: RUF012
            deadline = float("inf")

            def call(inner, service, operation, region, **kwargs):
                model = session.get_service_model(service)
                name = next(
                    name
                    for name in model.operation_names
                    if __import__("botocore").xform_name(name) == operation
                )
                validate_parameters(kwargs, model.operation_model(name).input_shape)
                calls.append((service, operation))
                if service == "sts":
                    return {"Account": "123456789012"}
                if operation == "get_metric_statistics":
                    return {"Datapoints": []}
                return {}

            def pages(
                inner, service, operation, region, result_key, item_limit=None, **kwargs
            ):
                inner.call(service, operation, region, **kwargs)
                return []

        collector = Collector(copy.deepcopy(DEFAULT), ValidatingAWS())
        collector.collect()
        for kind, name, arn in [
            ("APIGateway", "api", "arn:aws:apigateway:us-east-1::/restapis/test"),
            (
                "LoadBalancer",
                "lb",
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/123",
            ),
            (
                "Lambda",
                "function",
                "arn:aws:lambda:us-east-1:123456789012:function:function",
            ),
        ]:
            collector.asset(kind, name, arn, "us-east-1")
        network(collector, "us-east-1")
        metrics(collector, "us-east-1")
        self.assertIn(("apigateway", "get_resources"), calls)
        self.assertIn(("cloudwatch", "get_metric_statistics"), calls)

    def test_storage_drops_raw_payload_and_credentials(self):
        from phi_security.storage import Store

        store = Store(":memory:")
        self.addCleanup(store.close)
        store.put(
            "evidence",
            {
                "id": "e",
                "request_body": "raw patient",
                "nested": {"secret": "hidden"},
                "resource": "arn:example",
            },
        )
        value = store.get("evidence", "e")
        self.assertNotIn("raw patient", str(value))
        self.assertNotIn("hidden", str(value))
        self.assertEqual(value["resource"], "arn:example")

    def test_model_cannot_request_arbitrary_tools(self):
        response = Mock()
        response.read.return_value = json.dumps(
            {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Review",
                            "evidenceIds": ["e1"],
                            "queries": ["delete_bucket"],
                        }
                    )
                }
            }
        ).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with (
            patch("phi_security.llm.build_opener", return_value=opener),
            self.assertRaises(ValueError),
        ):
            Router({"llm": {"provider": "ollama", "model": "test"}}).query(
                "Review", [{"id": "e1"}], role="fast"
            )

    def test_classify_cli_and_dot_cli(self):
        import contextlib

        from phi_security.cli import main

        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "test.db")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["classify", "MRN: 12345", "--db", db])
            self.assertEqual(code, 0)
            self.assertEqual(
                json.loads(output.getvalue())["classification"], "PHI_HIGH"
            )
            graph = Path(directory) / "graph.dot"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["data-map", "--dot", str(graph), "--db", db]), 0)
            self.assertTrue(graph.read_text().startswith("digraph"))
            self.assertEqual(graph.stat().st_mode & 0o777, 0o600)

    def test_cli_blocks_hardlink_output_to_database(self):
        import contextlib

        from phi_security.cli import main
        from phi_security.storage import Store

        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "db.sqlite"
            Store(str(db)).close()
            target = Path(directory) / "other-name.json"
            os.link(db, target)
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main(["health", "--db", str(db), "--output", str(target)])
            self.assertEqual(raised.exception.code, 2)
            self.assertTrue(db.read_bytes().startswith(b"SQLite"))

    def test_permission_change_requires_prior_observation(self):
        from phi_security.changes import detect

        resource = {
            "id": "r",
            "arn": "arn:aws:s3:::b",
            "classification": "PHI",
            "type": "S3",
        }
        principal = {
            "id": "p",
            "arn": "arn:aws:iam::123456789012:role/test",
            "candidateResources": ["r"],
            "evidence": ["e"],
        }
        self.assertEqual(detect([resource], [principal], [], [], DEFAULT), [])
        result = detect(
            [resource],
            [principal],
            [{**principal, "candidateResources": []}],
            [],
            DEFAULT,
        )
        self.assertEqual(result[0]["type"], "NEW_SENSITIVE_PERMISSION")

    def test_incident_confidence_threshold_does_not_remove_finding(self):
        from test_system import fixture

        from phi_security.analysis import analyze

        data = fixture()
        findings, incidents, _ = analyze(
            data["resources"],
            data["principals"],
            data["evidence"],
            {**DEFAULT, "minimum_incident_confidence": 0.9},
        )
        self.assertTrue(any(f["type"] == "SENSITIVE_DATA_IN_LOGS" for f in findings))
        self.assertEqual(incidents, [])
