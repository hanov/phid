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
