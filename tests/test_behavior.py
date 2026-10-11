import copy
import unittest
from datetime import datetime, timedelta, timezone

from phi_security.behavior import detect as behavior
from phi_security.config import DEFAULT
from tests.helpers import fixture


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


class BehaviorBoundaryTest(unittest.TestCase):
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
