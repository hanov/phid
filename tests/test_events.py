import copy
import tempfile
import unittest
from unittest.mock import Mock

from phi_security.collect import Collector
from phi_security.config import DEFAULT
from phi_security.engine import Engine
from phi_security.events import unique_events
from tests.helpers import FakeCollector, fixture


class EventsWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

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


class EventsBoundaryTest(unittest.TestCase):
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
