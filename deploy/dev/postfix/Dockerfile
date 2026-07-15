# syntax=docker/dockerfile:1

# Postfix image for the Attachra local dev environment, pre-configured to
# hand outgoing mail to the Attachra milter (see main.cf). Based on the
# actively maintained boky/postfix image, which already provides
# Postfix + supervisord for container use and supports post-init hooks.
#
# The init hook directory this image actually executes is /docker-init.d/
# (see /scripts/run.sh -> execute_post_init_scripts() in /scripts/functions.sh
# at the pinned digest below). An older, unrelated Postfix image convention
# uses /docker-entrypoint-init.d/ instead; boky/postfix never reads that
# path, so a script placed there is silently skipped rather than failing
# loudly (this used to be a real bug here — Postfix looked healthy but
# smtpd_milters stayed empty, so mail passed through unprocessed). The
# smtpd_milters healthcheck in docker-compose.yml guards against a repeat
# of that failure mode regardless of its cause. Re-verify the init
# directory against /scripts/functions.sh whenever this digest is bumped.
FROM boky/postfix:latest@sha256:aafc772384232497bed875e1eb66b4d3e54ba1ebc86e2e185a6dc1dbc48182ef

COPY main.cf /etc/postfix/main.cf.attachra
COPY docker-init.d/10-attachra-main-cf.sh /docker-init.d/10-attachra-main-cf.sh
RUN chmod +x /docker-init.d/10-attachra-main-cf.sh
