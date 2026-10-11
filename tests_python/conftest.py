import pytest

_seen = set()
_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def pytest_configure(config):
    import phi_security.storage as _mod

    _orig_put = _mod.Store.put

    def _tracking_put(self, kind, data):
        if kind == "findings":
            fid = data.get("id")
            sev = data.get("severity", "").upper()
            if fid and fid not in _seen and sev in _counts:
                _seen.add(fid)
                _counts[sev] += 1
        return _orig_put(self, kind, data)

    _mod.Store.put = _tracking_put


@pytest.hookimpl(trylast=True)
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    c = _counts
    terminalreporter.write_line(
        f"--- critical {c['CRITICAL']}  high {c['HIGH']}  medium {c['MEDIUM']}  low {c['LOW']} ---",
        bold=True,
    )
