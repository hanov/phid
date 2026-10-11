import copy
import json
import unittest
from unittest.mock import Mock

from phi_security.aws import AWS
from phi_security.collect import Collector
from phi_security.config import DEFAULT
from phi_security.database import postgres_samples
from phi_security.discovery import config_history, database_samples, metrics, objects
from tests.helpers import fixture


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


class DiscoveryBoundaryTest(unittest.TestCase):
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
