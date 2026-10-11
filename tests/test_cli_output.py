import contextlib
import io
import unittest


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
