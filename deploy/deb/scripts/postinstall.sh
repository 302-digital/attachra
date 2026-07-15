#!/bin/sh
# postinst for the attachra Debian package.
#
# dpkg invokes `postinst configure <most-recently-configured-version>`:
# $2 is empty on a first install and set to the previous version on an
# upgrade — that distinction drives everything below.
#
# First install: Debian policy convention for a daemon package is
# enable+start. We deliberately deviate: attachra.yaml ships with a
# placeholder public_base_url ("https://mail.example.com") and
# policy.yaml ships scoped to a placeholder sender domain
# ("example.com") — starting the service before an operator edits both
# would either fail outright (an invalid public_base_url still passes
# config.Validate, since it only checks well-formedness, not whether
# the host is real) or silently apply the wrong policy/link host to
# real mail. So: enable (attachra starts automatically on future
# boots, once configured) but do NOT start now — the operator gets a
# clear, actionable message instead of an already-running daemon
# serving the wrong hostname.
#
# Upgrade: the operator has already configured and started attachra
# once, so silently leaving the OLD binary running until some later,
# unrelated restart would defeat the point of upgrading at all. Restart
# it — but only if it's actually running (`try-restart`, not
# `restart`): an operator who deliberately stopped attachra (e.g.
# during planned maintenance) should not have this upgrade start it
# back up behind their back. No first-install banner on this path —
# it would be noise on every routine upgrade.
set -e

case "$1" in
    configure)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl enable attachra.service >/dev/null 2>&1 || true
        fi

        if [ -z "$2" ]; then
            # First install.
            cat >&2 <<'EOF'

attachra installed but NOT started.

Before starting it, run the setup wizard (ATR-320) — it replaces the
placeholder attachra.yaml/policy.yaml this package shipped with a
config scoped to your real domain(s) and hostname, starting in safe
dry-run mode:

  1. sudo attachra setup
       (answers your sending domain(s), public hostname, storage
       backend, listen addresses and failure mode; add
       --non-interactive with flags for a scripted install — see
       `attachra setup --help`)
  2. Validate the policy file (setup already does this once, but
     re-check after any manual edit):
       attachra policy validate /etc/attachra/policy.yaml
  3. Start (and going forward, it starts automatically on boot):
       systemctl start attachra

Prefer to edit the YAML by hand instead? Skip step 1 and edit
/etc/attachra/attachra.yaml and /etc/attachra/policy.yaml directly —
see the full guide below for both paths.

Full guide: docs/deploy/grommunio-debian.md in the attachra source
tree, or https://attachra.org/docs/deploy/grommunio-debian (once
published).

EOF
        else
            # Upgrade from $2. Restart only if currently running, so a
            # deliberately-stopped instance stays stopped.
            if command -v systemctl >/dev/null 2>&1; then
                systemctl try-restart attachra.service >/dev/null 2>&1 || true
            fi
        fi
        ;;
esac

exit 0
