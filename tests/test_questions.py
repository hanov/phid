import copy
import tempfile
import unittest

from phi_security.config import DEFAULT
from phi_security.engine import Engine
from phi_security.questions import ask
from tests.helpers import FakeCollector, fixture


class QuestionsWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

    def test_natural_language_log_query(self):
        self.engine.scan({})
        result = ask(self.engine, "Was PHI written into logs today?", {})
        self.assertEqual(result["intent"], "log_leakage")
        self.assertEqual(len(result["records"]), 1)
        self.assertIn("from", result["timeRange"])

    def test_natural_language_no_evidence_does_not_assert_exfiltration(self):
        result = ask(self.engine, "Did PHI leave the production VPC?", {})
        self.assertEqual(result["records"], [])
        self.assertIn("do not prove", result["answer"])
