#!/usr/bin/env bash
# Attachra convenience installer.
#
# Usage:
#   curl -fsSL https://attachra.org/install | sudo bash
#
# What this does, in order:
#   1. Checks you're root and on a Debian-family system (amd64/arm64).
#   2. Resolves a version (latest GitHub release, or $ATTACHRA_VERSION).
#   3. Downloads the matching .deb and SHA256SUMS from GitHub Releases.
#   4. Verifies the checksum.
#   5. Installs it with apt.
#
# It does NOT touch Postfix, write config, or start the service — that's
# what `attachra setup` (run after this script) is for. Safe to re-run:
# apt treats it as an upgrade/reinstall, not an error.
#
# Trust model: the checksums come from the same GitHub release as the
# .deb, so this catches corruption, not a compromised release; artifact
# signing is tracked separately.
#
# Source: https://github.com/302-digital/attachra/blob/main/deploy/install.sh
set -euo pipefail

REPO="302-digital/attachra"
RELEASES="https://github.com/${REPO}/releases"
API="https://api.github.com/repos/${REPO}/releases/latest"
# Pin every curl call to HTTPS (and refuse to follow a redirect off it),
# and require TLS 1.2+, so a compromised resolver/proxy can't quietly
# downgrade us to plaintext or an outdated protocol version.
curl_opts=(--proto '=https' --proto-redir '=https' --tlsv1.2)

echo "==> Attachra installer"

# --- Root check ---------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "error: this script must run as root. Re-run with sudo:" >&2
  echo "  curl -fsSL https://attachra.org/install | sudo bash" >&2
  exit 1
fi

# --- Platform check ------------------------------------------------------
if ! command -v apt-get >/dev/null 2>&1; then
  echo "error: apt-get not found. Attachra ships Debian/Ubuntu packages only." >&2
  echo "  Releases and other install options: ${RELEASES}" >&2
  echo "  README: https://github.com/${REPO}#readme" >&2
  exit 1
fi

arch="$(dpkg --print-architecture)"
case "${arch}" in
  amd64|arm64) ;;
  *)
    echo "error: unsupported architecture '${arch}' (need amd64 or arm64)." >&2
    echo "  Releases: ${RELEASES}" >&2
    exit 1
    ;;
esac

# --- Resolve version -------------------------------------------------------
if [ -n "${ATTACHRA_VERSION:-}" ]; then
  tag="${ATTACHRA_VERSION}"
  echo "==> Using pinned version: ${tag}"
else
  echo "==> Looking up latest release..."
  # Fetch the full response before parsing it (not `curl | grep -m1`):
  # under `set -o pipefail`, grep -m1 closing the pipe early can make
  # curl exit non-zero with a write error even though the download
  # itself succeeded. Avoid a hard dependency on jq: pull tag_name out
  # with grep/sed instead.
  release_json="$(curl -fsSL "${curl_opts[@]}" "${API}")"
  tag="$(printf '%s\n' "${release_json}" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')"
  if [ -z "${tag}" ]; then
    echo "error: could not determine the latest release. Check ${RELEASES}" >&2
    exit 1
  fi
  echo "==> Latest version: ${tag}"
fi

# Guard against a malformed/malicious tag (e.g. from a tampered API
# response or an operator typo in $ATTACHRA_VERSION) before it's used to
# build download URLs and shell out to apt-get.
[[ "${tag}" =~ ^v[0-9A-Za-z.+_~-]+$ ]] || { echo "error: refusing suspicious version '${tag}'" >&2; exit 1; }

version="${tag#v}"
deb="attachra_${version}_${arch}.deb"

# --- Download into a temp dir, cleaned up on exit ---------------------------
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

echo "==> Downloading ${deb}..."
curl -fsSL "${curl_opts[@]}" -o "${tmpdir}/${deb}" "${RELEASES}/download/${tag}/${deb}"
curl -fsSL "${curl_opts[@]}" -o "${tmpdir}/SHA256SUMS" "${RELEASES}/download/${tag}/SHA256SUMS"

echo "==> Verifying checksum..."
(cd "${tmpdir}" && sha256sum -c --ignore-missing SHA256SUMS)

# --- Install -----------------------------------------------------------
# The leading "./" tells apt-get this is a local file, not a package name
# to look up in the apt cache.
echo "==> Installing ${deb}..."
(cd "${tmpdir}" && apt-get install -y "./${deb}")

echo
echo "==> Attachra ${tag} installed."
echo "Next steps:"
echo "  1. Run the setup wizard:   sudo attachra setup"
echo "     (it recommends starting in dry-run mode)"
echo "  2. Quickstart / Postfix integration:"
echo "     https://github.com/${REPO}#readme"
