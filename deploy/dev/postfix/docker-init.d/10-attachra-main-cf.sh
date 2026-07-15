#!/bin/sh
# Applies the Attachra dev main.cf settings on top of the boky/postfix
# base configuration. boky/postfix's run.sh sources every *.sh script
# found under /docker-init.d/ before starting Postfix (see
# execute_post_init_scripts() in /scripts/functions.sh).
#
# Since this script is sourced (". $f", not executed as a subprocess),
# `set -eu` would otherwise leak into run.sh's own shell and abort it
# later when it references its own optionally-unset variables (observed:
# run.sh crashing on an unbound $emphasis after sourcing this script with
# `set -u` in effect). Run our logic in a subshell so any `set` options
# stay local to it.
(
    set -eu

    MAIN_CF=/etc/postfix/main.cf
    OVERLAY=/etc/postfix/main.cf.attachra

    if [ -f "$OVERLAY" ]; then
        echo "" >> "$MAIN_CF"
        echo "# --- Attachra dev overlay ($OVERLAY) ---" >> "$MAIN_CF"
        cat "$OVERLAY" >> "$MAIN_CF"
    fi
)
