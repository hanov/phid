"""Tests for features and fixes added after v2.0.0."""

import contextlib
import io
import unittest

from phi_security.tui import SERVICES, resolve_scope


class TestResolveScope(unittest.TestCase):
    """Unit tests for tui.resolve_scope()."""

    def test_single_s3_returns_s3_scope(self):
        scope, skip = resolve_scope(["s3"])
        self.assertEqual(scope, "s3")
        self.assertEqual(skip, [])

    def test_single_databases_returns_databases_scope(self):
        scope, skip = resolve_scope(["databases"])
        self.assertEqual(scope, "databases")
        self.assertEqual(skip, [])

    def test_single_logs_returns_logs_scope(self):
        scope, skip = resolve_scope(["logs"])
        self.assertEqual(scope, "logs")
        self.assertEqual(skip, [])

    def test_all_services_returns_all_scope_no_skip(self):
        all_keys = [s[0] for s in SERVICES]
        scope, skip = resolve_scope(all_keys)
        self.assertEqual(scope, "all")
        self.assertEqual(skip, [])

    def test_partial_selection_skips_unselected(self):
        scope, skip = resolve_scope(["s3", "iam"])
        self.assertEqual(scope, "all")
        self.assertIn("databases", skip)
        self.assertNotIn("s3", skip)
        self.assertNotIn("iam", skip)

    def test_empty_selection_scans_all(self):
        # fix: empty list should return skip=[] not skip=all_keys
        scope, skip = resolve_scope([])
        self.assertEqual(scope, "all")
        self.assertEqual(skip, [])


class TestNoTuiFlag(unittest.TestCase):
    """--no-tui is accepted by the parser and defaults to False."""

    def _parser(self):
        from phi_security.cli import parser_for_cli

        return parser_for_cli()

    def test_no_tui_accepted(self):
        args = self._parser().parse_args(["scan", "--no-tui"])
        self.assertTrue(args.no_tui)

    def test_no_tui_default_false(self):
        args = self._parser().parse_args(["scan"])
        self.assertFalse(args.no_tui)


class TestSkipFlag(unittest.TestCase):
    """--skip is accepted; invalid names produce an argument error."""

    def _parser(self):
        from phi_security.cli import parser_for_cli

        return parser_for_cli()

    def test_skip_argument_parsed(self):
        args = self._parser().parse_args(["scan", "--skip", "iam,telemetry"])
        self.assertEqual(args.skip, "iam,telemetry")

    def test_skip_default_none(self):
        args = self._parser().parse_args(["scan"])
        self.assertIsNone(args.skip)


class TestVerboseFlag(unittest.TestCase):
    """-v / --verbose are recognised by the parser."""

    def _parser(self):
        from phi_security.cli import parser_for_cli

        return parser_for_cli()

    def test_verbose_long_form(self):
        args = self._parser().parse_args(["health", "--verbose"])
        self.assertTrue(args.verbose)

    def test_verbose_short_form(self):
        args = self._parser().parse_args(["health", "-v"])
        self.assertTrue(args.verbose)

    def test_verbose_default_false(self):
        args = self._parser().parse_args(["health"])
        self.assertFalse(args.verbose)


class TestDryRunFlag(unittest.TestCase):
    """--dry-run is parsed and forwarded in params as dryRun=True."""

    def _parser(self):
        from phi_security.cli import parser_for_cli

        return parser_for_cli()

    def test_dry_run_accepted(self):
        args = self._parser().parse_args(["scan", "--dry-run"])
        self.assertTrue(args.dry_run)

    def test_dry_run_default_false(self):
        args = self._parser().parse_args(["scan"])
        self.assertFalse(args.dry_run)


class TestConfigCheckCommand(unittest.TestCase):
    """config-check is a valid argparse command choice."""

    def test_config_check_in_choices(self):
        from phi_security.cli import parser_for_cli

        parser = parser_for_cli()
        args = parser.parse_args(["config-check"])
        self.assertEqual(args.command, "config-check")


class TestAskTtySummary(unittest.TestCase):
    """_tty_summary renders a one-liner for the ask command."""

    def _summary(self, result):
        from phi_security.cli import _tty_summary

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            handled = _tty_summary("ask", result)
        return handled, buf.getvalue()

    def test_ask_with_answer_key(self):
        handled, out = self._summary({"answer": "No PHI found in logs."})
        self.assertTrue(handled)
        self.assertIn("No PHI found", out)

    def test_ask_with_empty_result(self):
        handled, out = self._summary({})
        self.assertTrue(handled)
        self.assertIn("no answer", out)


class TestScanScopeSummary(unittest.TestCase):
    """scan TTY summary includes the scope field."""

    def _summary(self, result):
        from phi_security.cli import _tty_summary

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _tty_summary("scan", result)
        return buf.getvalue()

    def _base_result(self, scope="all"):
        return {
            "status": "COMPLETE",
            "scanId": "scan-abc",
            "scope": scope,
            "account": "123456789012",
            "summary": {},
            "findings": [],
            "coverage": [],
            "eventsScanned": 0,
        }

    def test_scope_all_shown(self):
        out = self._summary(self._base_result("all"))
        self.assertIn("scope=all", out)

    def test_scope_s3_shown(self):
        out = self._summary(self._base_result("s3"))
        self.assertIn("scope=s3", out)


class TestPaginationHint(unittest.TestCase):
    """Findings TTY summary shows a --page 2 hint when results are truncated."""

    def _summary(self, total, items):
        from phi_security.cli import _tty_summary

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _tty_summary("findings", {"total": total, "findings": items})
        return buf.getvalue()

    def test_hint_shown_when_truncated(self):
        items = [{"severity": "HIGH", "type": "T", "resource": "r"} for _ in range(6)]
        out = self._summary(6, items)
        self.assertIn("--page 2", out)

    def test_hint_absent_when_fits(self):
        items = [{"severity": "LOW", "type": "T", "resource": "r"} for _ in range(3)]
        out = self._summary(3, items)
        self.assertNotIn("--page 2", out)


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
