#!/usr/bin/env bash
# Attachra convenience uninstaller.
#
# Usage:
#   curl -fsSL https://attachra.org/uninstall | sudo bash
#
# What this does, in order:
#   1. Checks you're root.
#   2. Stops and disables the systemd service (if present).
#   3. Checks whether Postfix still points at Attachra's milter socket and,
#      if so, prints the exact postconf commands to remove it — it never
#      edits Postfix config itself.
#   4. Asks whether to remove just the package (default, keeps config and
#      stored files under /var/lib/attachra) or purge everything. A
#      non-interactive run (no tty, e.g. piped from curl) always keeps
#      config/data: purging is something an operator must choose deliberately.
#
# Source: https://github.com/302-digital/attachra/blob/main/deploy/uninstall.sh
set -euo pipefail

MILTER_PORT_MARKER="6785" # Attachra's default milter listen port.

echo "==> Attachra uninstaller"

# --- Root check ---------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "error: this script must run as root. Re-run with sudo:" >&2
  echo "  curl -fsSL https://attachra.org/uninstall | sudo bash" >&2
  exit 1
fi

# --- Stop and disable the service ----------------------------------------
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files attachra.service >/dev/null 2>&1; then
  echo "==> Stopping and disabling attachra.service..."
  systemctl stop attachra.service || true
  systemctl disable attachra.service || true
else
  echo "==> No attachra.service unit found, nothing to stop."
fi

# --- Warn about a still-wired Postfix milter chain ------------------------
if command -v postconf >/dev/null 2>&1; then
  for setting in smtpd_milters non_smtpd_milters; do
    value="$(postconf -h "${setting}" 2>/dev/null || true)"
    if [ -n "${value}" ] && printf '%s' "${value}" | grep -q "${MILTER_PORT_MARKER}"; then
      echo
      echo "warning: Postfix still references Attachra's milter port (${MILTER_PORT_MARKER}) in ${setting}:"
      echo "  ${setting} = ${value}"
      echo "Remove it yourself, e.g.:"
      echo "  sudo postconf -e '${setting} = <value with the attachra entry removed>'"
      echo "  sudo systemctl reload postfix"
    fi
  done
fi

# --- Decide remove vs purge ------------------------------------------------
mode="remove"
if [ -t 0 ] && [ -t 1 ]; then
  echo
  echo "Remove the attachra package only, or purge everything (config + service)?"
  echo "Note: this does NOT touch /var/lib/attachra (stored files, database) either"
  echo "way — files there may be under legal hold, and deleting them is a decision"
  echo "only you, the operator, should make."
  read -r -p "Remove package only (keep config) [default], or purge? [remove/purge]: " answer || answer=""
  case "${answer}" in
    [Pp]urge) mode="purge" ;;
    *) mode="remove" ;;
  esac
else
  echo "==> Non-interactive run: removing the package only (config kept)."
fi

# --- Remove or purge the package -------------------------------------------
if ! command -v apt-get >/dev/null 2>&1; then
  echo "error: apt-get not found; nothing to uninstall via apt on this system." >&2
  exit 1
fi

if [ "${mode}" = "purge" ]; then
  echo "==> Purging the attachra package (removes /etc/attachra config too)..."
  apt-get purge -y attachra
else
  echo "==> Removing the attachra package (config under /etc/attachra is kept)..."
  apt-get remove -y attachra
fi

echo
echo "==> Done. /var/lib/attachra (stored files, database, audit log) was left"
echo "    untouched — remove it manually once you're sure nothing there needs"
echo "    to be retained."
