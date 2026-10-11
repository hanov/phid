import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from phi_security.analysis import analyze, baseline, permissions
from phi_security.collect import Collector
from phi_security.config import DEFAULT
from phi_security.privacy import detect
from tests.helpers import fixture


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
