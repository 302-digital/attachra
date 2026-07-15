#!/bin/sh
# Applies the Attachra dev main.cf settings on top of the boky/postfix
# base configuration. boky/postfix runs every executable script under
# /docker-entrypoint-init.d/ before starting Postfix.
set -eu

MAIN_CF=/etc/postfix/main.cf
OVERLAY=/etc/postfix/main.cf.attachra

if [ -f "$OVERLAY" ]; then
    echo "" >> "$MAIN_CF"
    echo "# --- Attachra dev overlay ($OVERLAY) ---" >> "$MAIN_CF"
    cat "$OVERLAY" >> "$MAIN_CF"
fi
