import copy
import tempfile
import unittest

from phi_security.config import DEFAULT
from phi_security.engine import Engine
from phi_security.privacy import detect, merge_classification
from tests.helpers import FakeCollector, fixture


class PrivacyWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

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
