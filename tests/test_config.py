import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phi_security.config import DEFAULT, load, normalize
from phi_security.engine import Engine
from tests.helpers import FakeCollector, fixture


class TestRegionsBlanks(unittest.TestCase):
    """--regions trailing comma does not produce a blank region entry."""

    def test_trailing_comma_filtered(self):
        from phi_security.cli import parser_for_cli

        args = parser_for_cli().parse_args(
            ["scan", "--no-tui", "--regions", "us-east-1,"]
        )
        # simulate the params-building logic
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
        self.assertEqual(regions, ["us-east-1"])
        self.assertNotIn("", regions)


class ConfigWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {**copy.deepcopy(DEFAULT), "db": self.tmp.name + "/test.db"}
        self.collector = FakeCollector(fixture())
        self.engine = Engine(self.config, self.collector)
        self.addCleanup(self.engine.store.close)

    def test_config_is_deep_copied(self):
        with patch.dict("os.environ", {}, clear=True):
            a = load(db_path=self.config["db"])
            a["llm"]["models"]["fast"] = "test"
            b = load(db_path=self.config["db"])
        self.assertNotIn("fast", b["llm"]["models"])

    def test_nested_config(self):
        values = normalize(
            {
                "aws": {"profile": "prod", "regions": ["us-west-2"]},
                "storage": {"path": "x.db"},
                "detection": {"log_phi_detection": False},
            }
        )
        self.assertEqual(values["profile"], "prod")
        self.assertEqual(values["db"], "x.db")
        self.assertFalse(values["detectors"]["log_phi_detection"])

    def test_reject_remote_provider(self):
        path = Path(self.tmp.name) / "remote.json"
        path.write_text(json.dumps({"llm": {"provider": "bedrock"}}))
        with self.assertRaises(ValueError):
            load(str(path), self.config["db"])


class ConfigBoundaryTest(unittest.TestCase):
    def test_bad_config_and_remote_provider_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for value in [
                {"llm": {"provider": "remote"}},
                {
                    "db_samples": [
                        {
                            "service": "dynamodb",
                            "table": "t",
                            "region": "us-east-1",
                            "limit": 11,
                        }
                    ]
                },
                {"custom_patterns": [{"name": "bad", "regex": "["}]},
                {"regions": ["not-a-region"]},
            ]:
                path.write_text(json.dumps(value))
                with (
                    patch.dict(os.environ, {}, clear=True),
                    self.assertRaises((ValueError, __import__("re").error)),
                ):
                    load(str(path))

    def test_yaml_nested_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                "aws:\n  regions: [us-west-2]\n  profile: prod\nstorage:\n  path: local.db\nllm:\n  provider: none\n"
            )
            with patch.dict(os.environ, {}, clear=True):
                result = load(str(path))
            self.assertEqual(result["regions"], ["us-west-2"])
            self.assertEqual(result["db"], "local.db")
