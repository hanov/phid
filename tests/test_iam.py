import copy
import tempfile
import unittest

from phi_security.analysis import permissions
from phi_security.config import DEFAULT
from phi_security.engine import Engine
from tests.helpers import FakeCollector, fixture


class IamWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

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


class IamBoundaryTest(unittest.TestCase):
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
