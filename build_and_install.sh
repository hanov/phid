#!/bin/sh
# Build phid from source and install it locally.
# Binary builds require macOS Apple Silicon; all other platforms use pip install.
#
# Usage:
#   sh build_and_install.sh                   # installs to /opt/homebrew/bin
#   PHID_INSTALL_DIR=~/.local/bin sh build_and_install.sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${PHID_INSTALL_DIR:-/opt/homebrew/bin}"
VENV="$ROOT/.venv-build"

# ── platform check ──────────────────────────────────────────────────────────
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo 'Binary build is supported on macOS Apple Silicon only.' >&2
    echo 'On other platforms install from source: pip install .[databases]' >&2
    exit 1
fi

# ── build venv ───────────────────────────────────────────────────────────────
if [ ! -f "$VENV/bin/python" ]; then
    echo '==> Creating build virtual environment...'
    python3 -m venv "$VENV"
fi

echo '==> Installing build dependencies...'
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$ROOT[databases]"
"$VENV/bin/pip" install --quiet 'pyinstaller>=6,<7'

# ── build ────────────────────────────────────────────────────────────────────
echo '==> Building phid binary...'
"$VENV/bin/python" "$ROOT/packaging/build_binary.py"

# ── install ──────────────────────────────────────────────────────────────────
echo "==> Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
install -m 755 "$ROOT/dist/phid" "$INSTALL_DIR/phid"

echo "Installed: $INSTALL_DIR/phid"
"$INSTALL_DIR/phid" --version
