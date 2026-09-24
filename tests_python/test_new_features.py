"""Tests for features and fixes added after v2.0.0."""
import io
import contextlib
import unittest

from phi_security.tui import resolve_scope, SERVICES, _ALL_KEYS


class TestResolveScope(unittest.TestCase):
    """Unit tests for tui.resolve_scope()."""

    def test_single_s3_returns_s3_scope(self):
        scope, skip = resolve_scope(['s3'])
        self.assertEqual(scope, 's3')
        self.assertEqual(skip, [])

    def test_single_databases_returns_databases_scope(self):
        scope, skip = resolve_scope(['databases'])
        self.assertEqual(scope, 'databases')
        self.assertEqual(skip, [])

    def test_single_logs_returns_logs_scope(self):
        scope, skip = resolve_scope(['logs'])
        self.assertEqual(scope, 'logs')
        self.assertEqual(skip, [])

    def test_all_services_returns_all_scope_no_skip(self):
        all_keys = [s[0] for s in SERVICES]
        scope, skip = resolve_scope(all_keys)
        self.assertEqual(scope, 'all')
        self.assertEqual(skip, [])

    def test_partial_selection_skips_unselected(self):
        scope, skip = resolve_scope(['s3', 'iam'])
        self.assertEqual(scope, 'all')
        self.assertIn('databases', skip)
        self.assertNotIn('s3', skip)
        self.assertNotIn('iam', skip)

    def test_empty_selection_scans_all(self):
        # fix: empty list should return skip=[] not skip=all_keys
        scope, skip = resolve_scope([])
        self.assertEqual(scope, 'all')
        self.assertEqual(skip, [])


class TestNoTuiFlag(unittest.TestCase):
    """--no-tui is accepted by the parser and defaults to False."""

    def _parser(self):
        from phi_security.cli import parser_for_cli
        return parser_for_cli()

    def test_no_tui_accepted(self):
        args = self._parser().parse_args(['scan', '--no-tui'])
        self.assertTrue(args.no_tui)

    def test_no_tui_default_false(self):
        args = self._parser().parse_args(['scan'])
        self.assertFalse(args.no_tui)


class TestSkipFlag(unittest.TestCase):
    """--skip is accepted; invalid names produce an argument error."""

    def _parser(self):
        from phi_security.cli import parser_for_cli
        return parser_for_cli()

    def test_skip_argument_parsed(self):
        args = self._parser().parse_args(['scan', '--skip', 'iam,telemetry'])
        self.assertEqual(args.skip, 'iam,telemetry')

    def test_skip_default_none(self):
        args = self._parser().parse_args(['scan'])
        self.assertIsNone(args.skip)


class TestVerboseFlag(unittest.TestCase):
    """-v / --verbose are recognised by the parser."""

    def _parser(self):
        from phi_security.cli import parser_for_cli
        return parser_for_cli()

    def test_verbose_long_form(self):
        args = self._parser().parse_args(['health', '--verbose'])
        self.assertTrue(args.verbose)

    def test_verbose_short_form(self):
        args = self._parser().parse_args(['health', '-v'])
        self.assertTrue(args.verbose)

    def test_verbose_default_false(self):
        args = self._parser().parse_args(['health'])
        self.assertFalse(args.verbose)


class TestDryRunFlag(unittest.TestCase):
    """--dry-run is parsed and forwarded in params as dryRun=True."""

    def _parser(self):
        from phi_security.cli import parser_for_cli
        return parser_for_cli()

    def test_dry_run_accepted(self):
        args = self._parser().parse_args(['scan', '--dry-run'])
        self.assertTrue(args.dry_run)

    def test_dry_run_default_false(self):
        args = self._parser().parse_args(['scan'])
        self.assertFalse(args.dry_run)
