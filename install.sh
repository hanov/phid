#!/bin/sh
# phid standalone installer. No application server is installed or started.
set -eu
base_url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --base-url) [ "$#" -ge 2 ] || { echo 'Missing --base-url value' >&2; exit 2; }; base_url=${2%/}; shift 2 ;;
        --help|-h) echo 'Usage: sh install.sh --base-url https://your-site.example'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$base_url" in https://*) ;; *) echo 'Provide the HTTPS site URL using --base-url.' >&2; exit 2 ;; esac
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || { echo 'This binary supports macOS Apple Silicon only. Use the Python source on other platforms.' >&2; exit 1; }
for tool in curl shasum install mktemp; do command -v "$tool" >/dev/null || { echo "Required command missing: $tool" >&2; exit 1; }; done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/dist"
curl --proto '=https' --proto-redir '=https' -fsSL "$base_url/dist/phid" -o "$work/dist/phid"
curl --proto '=https' --proto-redir '=https' -fsSL "$base_url/dist/phid.sha256" -o "$work/checksum"
expected=$(awk 'NR == 1 {print $1}' "$work/checksum")
[ "${#expected}" -eq 64 ] || { echo 'Invalid checksum.' >&2; exit 1; }
case "$expected" in *[!0-9a-fA-F]*) echo 'Invalid checksum.' >&2; exit 1 ;; esac
actual=$(shasum -a 256 "$work/dist/phid")
actual=${actual%% *}
[ "$actual" = "$expected" ] || { echo 'Checksum verification failed.' >&2; exit 1; }
destination=${PHID_INSTALL_DIR:-"$HOME/.local/bin"}
mkdir -p "$destination"
install -m 755 "$work/dist/phid" "$destination/phid"
printf 'Installed phid to %s/phid\n' "$destination"
printf 'Ensure %s is on PATH, then run: phid --man\n' "$destination"
