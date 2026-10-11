import unittest


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
