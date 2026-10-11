import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phi_security.cli import main
from phi_security.engine import Engine
from phi_security.report import render_dashboard
from phi_security.storage import Store


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / "test.db")
        self.html = Path(self.temp.name) / "scan-report.html"
        store = Store(self.db)
        for i in range(25):
            store.put(
                "findings",
                {
                    "id": f"finding-{i:03}",
                    "severity": "HIGH" if i else "LOW",
                    "title": '<script>alert("x")</script>',
                    "status": "OPEN",
                    "evidence": ["e1"],
                },
            )
        store.put("evidence", {"id": "e1", "source": "test", "eventType": "Observed"})
        store.meta(
            "lastScan",
            {
                "scanId": "scan-test",
                "status": "PARTIAL",
                "coverage": [{"service": "s3", "status": "AccessDenied"}],
            },
        )
        store.commit()
        store.close()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*args, "--db", self.db, "--html", str(self.html)])
        return code, out.getvalue(), err.getvalue()

    def test_offline_report_complete_escaped_and_private(self):
        with patch(
            "phi_security.engine.Collector",
            side_effect=AssertionError("must stay offline"),
        ):
            code, out, err = self.run_cli("report")
        self.assertEqual(code, 0, err)
        html = self.html.read_text()
        for i in range(25):
            self.assertIn(f"finding-{i:03}", html)
        self.assertIn("All findings (25)", html)
        self.assertIn("PARTIAL", html)
        self.assertIn("AccessDenied", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("https://", html)
        self.assertEqual(self.html.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(json.loads(out)["findings"]), 25)

    def test_html_ignores_query_filters_but_json_does_not(self):
        code, out, err = self.run_cli("findings", "--severity", "LOW", "--limit", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["total"], 1)
        self.assertIn("All findings (25)", self.html.read_text())

    def test_scan_writes_json_and_html(self):
        target = Path(self.temp.name) / "scan.json"
        with patch.object(
            Engine, "scan", return_value={"status": "PARTIAL", "scanId": "new-scan"}
        ):
            code, out, err = self.run_cli("scan", "--output", str(target))
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(target.read_text())["scanId"], "new-scan")
        self.assertIn("new-scan", self.html.read_text())

    def test_failed_agent_updates_dashboard(self):
        with patch.object(Engine, "scan", side_effect=RuntimeError("private error")):
            code, _out, _err = self.run_cli("agent", "--once")
        self.assertEqual(code, 1)
        self.assertIn("FAILED", self.html.read_text())
        self.assertNotIn("private error", self.html.read_text())

    def test_rejects_path_collision_and_unsupported_command(self):
        for args in [("report", "--output", str(self.html)), ("health",)]:
            with self.assertRaises(SystemExit) as raised:
                self.run_cli(*args)
            self.assertEqual(raised.exception.code, 2)
        self.html = Path(self.db)
        with self.assertRaises(SystemExit) as raised:
            self.run_cli("report")
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(Path(self.db).read_bytes()[:6], b"SQLite")

    def test_empty_state(self):
        html = render_dashboard(
            {
                "generatedAt": "now",
                "account": None,
                "lastScan": None,
                "findings": [],
                "resources": [],
                "incidents": [],
                "evidence": [],
            }
        )
        self.assertIn("NOT SCANNED", html)
        self.assertIn("All findings (0)", html)
        self.assertIn("No records available.", html)

    def test_write_failure_exits_nonzero(self):
        self.html = Path(self.temp.name) / "missing" / "report.html"
        code, out, err = self.run_cli("report")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["errorType"], "FileNotFoundError")
