import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phi_security.cli import main
from phi_security.config import load
from phi_security.engine import Engine
from phi_security.storage import Store


class CLITest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / "test.db")

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*args, "--db", self.db])
        return code, out.getvalue(), err.getvalue()

    def test_manual_does_not_initialize_engine(self):
        with patch("phi_security.cli.Engine", side_effect=AssertionError):
            for arg in ["--man", "man"]:
                code, out, _err = self.run_cli(arg, "--config", "/nonexistent")
                self.assertEqual(code, 0)
                self.assertIn("PHID(1)", out)
                self.assertFalse(Path(self.db).exists())

    def test_module_entrypoints(self):
        for module in ["phi_security", "phi_security.cli"]:
            result = subprocess.run(
                [sys.executable, "-m", module, "--man"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("EXIT STATUS", result.stdout)

    def test_stored_queries_never_collect(self):
        with patch("phi_security.engine.Collector", side_effect=AssertionError):
            for command in [
                "health",
                "inventory",
                "findings",
                "evidence",
                "data-map",
                "iam",
                "logs",
                "exposure",
                "incidents",
                "investigations",
                "baselines",
                "cycles",
                "classifications",
            ]:
                code, out, err = self.run_cli(command)
                self.assertEqual(code, 0, err)
                self.assertIsInstance(json.loads(out), dict)

    def test_ask_searches_local_records(self):
        store = Store(self.db)
        store.put(
            "findings",
            {
                "id": "f1",
                "type": "PUBLIC_SENSITIVE_DATA",
                "detail": "patient@example.com",
            },
        )
        store.commit()
        store.close()
        code, out, err = self.run_cli("ask", "public")
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["matches"][0]["record"]["id"], "f1")
        self.assertNotIn("patient@example.com", out)

    def test_output_is_private_and_stdout_empty(self):
        target = Path(self.temp.name) / "result.json"
        target.write_text("old")
        target.chmod(0o644)
        code, out, err = self.run_cli("health", "--output", str(target))
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(target.read_text())["status"], "ok")

    def test_argument_errors_precede_database_creation(self):
        for args in [
            [],
            ["ask"],
            ["incident"],
            ["evidence", "--to", "now"],
            ["iam", "--activity"],
            ["scan", "--view", "public"],
            ["health", "--limit", "0"],
        ]:
            with self.subTest(args=args), self.assertRaises(SystemExit) as raised:
                self.run_cli(*args)
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(Path(self.db).exists())

    def test_agent_failure_exits_nonzero_and_persists_cycle(self):
        with patch.object(
            Engine, "scan", side_effect=RuntimeError("sensitive failure")
        ):
            code, out, err = self.run_cli("agent", "--once")
        self.assertEqual(code, 1)
        self.assertNotIn("sensitive failure", out + err)
        code, out, err = self.run_cli("cycles")
        result = json.loads(out)
        self.assertEqual(result["totalCycles"], 1)
        self.assertEqual(result["cycles"][0]["status"], "FAILED")

    def test_scan_scope_and_time_range_forwarded(self):
        with patch.object(Engine, "scan", return_value={"status": "COMPLETED"}) as scan:
            code, _out, err = self.run_cli("scan", "--scope", "logs", "--from", "24h")
        self.assertEqual(code, 0, err)
        params, scope = scan.call_args.args
        self.assertEqual(scope, "logs")
        self.assertEqual(params["timeRange"], {"from": "24h"})
        self.assertNotIn("from", params)  # Do not filter resources by evidence dates.

    def test_evidence_time_filter(self):
        store = Store(self.db)
        store.put(
            "evidence",
            {"id": "old", "source": "test", "timestamp": "2000-01-01T00:00:00Z"},
        )
        store.commit()
        store.close()
        code, out, err = self.run_cli("evidence", "--from", "24h")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["total"], 0)

    def test_config_override_without_environment_mutation(self):
        path = Path(self.temp.name) / "config.json"
        path.write_text(json.dumps({"db": "configured.db"}))
        with patch.dict(os.environ, {"PHI_DB": "environment.db"}):
            self.assertEqual(load(str(path), self.db)["db"], self.db)
            self.assertEqual(os.environ["PHI_DB"], "environment.db")

    def test_failure_is_stderr_and_nonzero(self):
        code, out, err = self.run_cli("incident", "missing")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["status"], 404)


class CliBoundaryTest(unittest.TestCase):
    def test_classify_cli_and_dot_cli(self):
        import contextlib

        from phi_security.cli import main

        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "test.db")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["classify", "MRN: 12345", "--db", db])
            self.assertEqual(code, 0)
            self.assertEqual(
                json.loads(output.getvalue())["classification"], "PHI_HIGH"
            )
            graph = Path(directory) / "graph.dot"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["data-map", "--dot", str(graph), "--db", db]), 0)
            self.assertTrue(graph.read_text().startswith("digraph"))
            self.assertEqual(graph.stat().st_mode & 0o777, 0o600)

    def test_cli_blocks_hardlink_output_to_database(self):
        import contextlib

        from phi_security.cli import main
        from phi_security.storage import Store

        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "db.sqlite"
            Store(str(db)).close()
            target = Path(directory) / "other-name.json"
            os.link(db, target)
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main(["health", "--db", str(db), "--output", str(target)])
            self.assertEqual(raised.exception.code, 2)
            self.assertTrue(db.read_bytes().startswith(b"SQLite"))
