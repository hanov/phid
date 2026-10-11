import os
import unittest
from datetime import datetime, timezone

from phi_security.config import DEFAULT
from tests.helpers import fixture


class CorrelationBoundaryTest(unittest.TestCase):
    def test_incident_confidence_threshold_does_not_remove_finding(self):
        from phi_security.analysis import analyze
        from tests.helpers import fixture

        data = fixture()
        findings, incidents, _ = analyze(
            data["resources"],
            data["principals"],
            data["evidence"],
            {**DEFAULT, "minimum_incident_confidence": 0.9},
        )
        self.assertTrue(any(f["type"] == "SENSITIVE_DATA_IN_LOGS" for f in findings))
        self.assertEqual(incidents, [])


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
