#!/bin/sh
# postrm for the attachra Debian package.
set -e

case "$1" in
    remove)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --quiet stop attachra.service >/dev/null 2>&1 || true
            systemctl disable attachra.service >/dev/null 2>&1 || true
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi
        ;;
    purge)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --quiet stop attachra.service >/dev/null 2>&1 || true
            systemctl disable attachra.service >/dev/null 2>&1 || true
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi

        # Deliberately NOT removed on purge: /var/lib/attachra (sqlite
        # metadata DB and any fs-driver attachment payloads) and
        # /etc/attachra/attachra.env (operator-managed secrets, not
        # packaged by us in the first place). Attachment metadata can
        # be under active legal hold (ATR-257/258) or otherwise
        # audit-relevant; deleting it silently on `apt purge` is not a
        # call this script gets to make. Remove manually if intended:
        #   rm -rf /var/lib/attachra /etc/attachra/attachra.env
        ;;
esac

exit 0
