import copy
import tempfile
import unittest

from phi_security.config import DEFAULT
from phi_security.controls import assess
from phi_security.engine import Engine
from tests.helpers import FakeCollector, fixture


class ControlsWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

    def test_controls_unknown_not_passed(self):
        resources = fixture()["resources"]
        controls = assess(resources, [], [])
        self.assertGreater(controls["summary"]["UNKNOWN"], 0)
        self.assertIn("No legal", controls["assessment"])
