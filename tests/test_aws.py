import json
import unittest
from unittest.mock import Mock

from phi_security.aws import ALLOW, AWS
from phi_security.config import DEFAULT


class AwsBoundaryTest(unittest.TestCase):
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
