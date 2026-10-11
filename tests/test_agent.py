import copy
import tempfile
import unittest

from phi_security.agent import triage
from phi_security.config import DEFAULT
from phi_security.engine import Engine
from tests.helpers import FakeCollector, fixture


class AgentWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

    def test_agent_does_not_repeat_same_evidence_review(self):
        report = self.engine.scan({})
        first = triage(self.engine, report)
        second = triage(self.engine, report)
        self.assertTrue(first)
        self.assertEqual(second, [])
