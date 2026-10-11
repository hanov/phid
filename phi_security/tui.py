"""Interactive terminal UI: pre-scan configurator and animated scan progress."""

import curses
import datetime as _dt
import logging
import sys
import threading
import time
from typing import ClassVar

VERSION = "2.0.0"
_YEAR = _dt.date.today().year
COPYRIGHT = (
    f"2024 - {_YEAR} Oleksandr Amirkhanov"
    if _YEAR > 2024
    else "2024 Oleksandr Amirkhanov"
)
LICENSE = "PolyForm Noncommercial"

SERVICES = [
    ("s3", "S3 Buckets", "object storage · policies · ACLs · encryption"),
    ("iam", "IAM", "roles · users · permissions · trust"),
    ("databases", "Databases", "RDS · Aurora · DynamoDB · Redshift · OpenSearch"),
    ("logs", "Logs", "CloudWatch log groups · PHI/PII in messages"),
    ("infrastructure", "Infrastructure", "EC2 · Lambda · ECS · EKS · KMS · Backup"),
    ("telemetry", "Telemetry", "CloudTrail management events"),
    ("integrations", "Integrations", "Macie · GuardDuty · SecurityHub · Config"),
]

_ALL_KEYS = [s[0] for s in SERVICES]


def resolve_scope(selected):
    """Map a list of selected service keys to (scope_str, skip_services_list)."""
    sel = set(selected)
    if not sel:
        return "all", []
    if sel == {"s3"}:
        return "s3", []
    if sel == {"databases"}:
        return "databases", []
    if sel == {"logs"}:
        return "logs", []
    skip = [k for k in _ALL_KEYS if k not in sel]
    return "all", skip


# ── launch UI ─────────────────────────────────────────────────────────────────


def launch(config):
    """
    Show the interactive pre-scan configurator.
    Returns (scope, skip_services) or raises SystemExit(0) on quit.
    """
    try:
        result = curses.wrapper(_run_launch, config)
    except curses.error:
        return "all", []  # fallback: terminal too small / no curses
    if result is None:
        raise SystemExit(0)
    return result


_N_SVC = len(SERVICES)

# Bottom action indices (after all service rows)
_ACT_ALL = _N_SVC  # Check All
_ACT_NONE = _N_SVC + 1  # Uncheck All
_ACT_START = _N_SVC + 2  # Start Scan
_ACT_QUIT = _N_SVC + 3  # Quit
_TOTAL = _N_SVC + 4


def _run_launch(stdscr, config):
    curses.curs_set(0)

    checked = [True] * _N_SVC
    cursor = 0
    tick = 0
    SPIN = ["*", "+", "x", "+", "*", ".", "*", "."]

    stdscr.timeout(500)  # ms per frame — matches 0.5 s blink

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        spin = SPIN[tick % len(SPIN)]
        tick += 1

        def put(r, c, text, attr=0, _h=h, _w=w):
            try:
                if 0 <= r < _h and 0 <= c < _w:
                    stdscr.addnstr(r, c, text, max(0, _w - c - 1), attr)
            except curses.error:
                pass

        # ── border ────────────────────────────────────────────────────────
        try:
            stdscr.box()
        except curses.error:
            pass

        # ── header ────────────────────────────────────────────────────────
        put(0, 2, f"  phid  —  AWS PHI/PII Scanner  v{VERSION}  ", curses.A_BOLD)
        put(0, w - 4, f"{spin}  ", curses.A_BOLD)
        put(1, 3, f"(c) {COPYRIGHT}   {LICENSE}", curses.A_DIM)

        try:
            stdscr.hline(2, 1, curses.ACS_HLINE, w - 2)
        except curses.error:
            pass

        put(3, 3, "SCAN TARGETS", curses.A_BOLD)

        # ── service list ──────────────────────────────────────────────────
        for i, (key, label, desc) in enumerate(SERVICES):
            row = 5 + i
            if row >= h - 4:
                break
            is_cur = cursor == i
            arrow = ">" if is_cur else " "
            box = "[x]" if checked[i] else "[ ]"
            row_attr = curses.A_BOLD if is_cur else curses.A_NORMAL
            box_attr = curses.A_BOLD if checked[i] else curses.A_DIM

            put(row, 3, arrow, row_attr)
            put(row, 5, box, box_attr)
            put(row, 9, f"{label:<16}", row_attr)
            dx = 9 + 17
            if dx + len(desc) < w - 3:
                put(row, dx, desc, curses.A_DIM)

        # ── regions ───────────────────────────────────────────────────────
        reg_row = 5 + _N_SVC + 1
        put(
            reg_row,
            3,
            "Regions  " + ", ".join(config.get("regions", ["us-east-1"])),
            curses.A_NORMAL,
        )

        # ── bottom separator ──────────────────────────────────────────────
        sep = reg_row + 1
        try:
            stdscr.hline(sep, 1, curses.ACS_HLINE, w - 2)
        except curses.error:
            pass

        # ── action row 1: Check All  |  Uncheck All  |  nav hint ─────────
        def act(row, col, label, idx, _cursor=cursor):
            is_cur = _cursor == idx
            put(
                row,
                max(0, col - 2),
                ">" if is_cur else " ",
                curses.A_BOLD if is_cur else curses.A_NORMAL,
            )
            put(row, col, label, curses.A_BOLD if is_cur else curses.A_DIM)

        act(sep + 1, 3, "Check All", _ACT_ALL)
        act(sep + 1, 18, "Uncheck All", _ACT_NONE)
        put(sep + 1, w - 26, "Up/Down navigate   Space toggle", curses.A_DIM)

        # ── action row 2: Start Scan  |  Quit ────────────────────────────
        act(sep + 2, 3, "Start Scan", _ACT_START)
        act(sep + 2, w - 10, "Quit", _ACT_QUIT)

        stdscr.refresh()

        # ── key handling ──────────────────────────────────────────────────
        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):
            return None
        elif key in (curses.KEY_UP, ord("k")):
            cursor = (cursor - 1) % _TOTAL
        elif key in (curses.KEY_DOWN, ord("j")):
            cursor = (cursor + 1) % _TOTAL
        elif key in (ord("a"), ord("A")):
            checked = [True] * _N_SVC
        elif key in (ord("n"), ord("N")):
            checked = [False] * _N_SVC
        elif key == ord(" "):
            if cursor < _N_SVC:
                checked[cursor] = not checked[cursor]
            elif cursor == _ACT_ALL:
                checked = [True] * _N_SVC
            elif cursor == _ACT_NONE:
                checked = [False] * _N_SVC
            elif cursor == _ACT_START:
                selected = [SERVICES[i][0] for i in range(_N_SVC) if checked[i]]
                if selected:
                    return resolve_scope(selected)
            elif cursor == _ACT_QUIT:
                return None
        elif key in (10, 13, curses.KEY_ENTER):
            if cursor < _N_SVC:
                selected = [SERVICES[i][0] for i in range(_N_SVC) if checked[i]]
                if selected:
                    return resolve_scope(selected)
            elif cursor == _ACT_ALL:
                checked = [True] * _N_SVC
            elif cursor == _ACT_NONE:
                checked = [False] * _N_SVC
            elif cursor == _ACT_START:
                selected = [SERVICES[i][0] for i in range(_N_SVC) if checked[i]]
                if selected:
                    return resolve_scope(selected)
            elif cursor == _ACT_QUIT:
                return None


# ── scan progress indicator ───────────────────────────────────────────────────


class ScanProgress:
    """
    Animated bottom-line status bar while a scan runs.

    Displays a blinking asterisk + elapsed timer + current log action.
    Intercepts the root logger so log messages scroll above the bar cleanly.

    Usage::

        progress = ScanProgress()
        progress.start()
        ...  # logging.info() calls appear as scrolling lines above bar
        progress.stop()
    """

    # Two-frame blink: bold * on for 0.5 s, off for 0.5 s
    _FRAMES: ClassVar[list[str]] = ["\033[1m*\033[0m", " "]

    def __init__(self, stream=None):
        self._stream = stream or sys.stderr
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._start = time.monotonic()
        self._current = "starting..."
        self._thread = None
        self._old_handlers = []
        self._old_level = logging.NOTSET

    # ── public ────────────────────────────────────────────────────────────────

    def start(self):
        self._install_logging()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        with self._lock:
            print("\r\033[K", end="", file=self._stream, flush=True)
        self._restore_logging()

    # ── animation ─────────────────────────────────────────────────────────────

    def _elapsed(self):
        t = time.monotonic() - self._start
        return f"{int(t // 60)}:{int(t % 60):02d}"

    def _animate(self):
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            elapsed = self._elapsed()
            with self._lock:
                msg = self._current[:72]
                status = f"\r {frame} {elapsed}  \033[2m{msg}\033[0m\033[K"
                print(status, end="", file=self._stream, flush=True)
            i += 1
            self._stop.wait(0.5)

    # ── logging plumbing ──────────────────────────────────────────────────────

    def _install_logging(self):
        root = logging.getLogger()
        self._old_handlers = list(root.handlers)
        self._old_level = root.level
        root.handlers.clear()
        h = _ProgressHandler(self)
        h.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(h)
        root.setLevel(logging.INFO)

    def _restore_logging(self):
        root = logging.getLogger()
        root.handlers.clear()
        for h in self._old_handlers:
            root.addHandler(h)
        root.setLevel(self._old_level)


class _ProgressHandler(logging.Handler):
    """Clears the status bar before each log message so they scroll cleanly."""

    def __init__(self, progress):
        super().__init__()
        self._p = progress

    def emit(self, record):
        p = self._p
        msg = self.format(record)
        with p._lock:
            # erase status bar → print message (scrolls) → bar redraws next tick
            print(f"\r\033[K{msg}", file=p._stream, flush=True)
            p._current = msg.strip()
