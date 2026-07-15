# syntax=docker/dockerfile:1

# Postfix image for the Attachra local dev environment, pre-configured to
# hand outgoing mail to the Attachra milter (see main.cf). Based on the
# actively maintained boky/postfix image, which already provides
# Postfix + supervisord for container use and supports post-init hooks
# via /docker-entrypoint-init.d/*.sh (see boky/postfix documentation).
FROM boky/postfix:latest@sha256:aafc772384232497bed875e1eb66b4d3e54ba1ebc86e2e185a6dc1dbc48182ef

COPY main.cf /etc/postfix/main.cf.attachra
COPY docker-entrypoint-init.d/10-attachra-main-cf.sh /docker-entrypoint-init.d/10-attachra-main-cf.sh
RUN chmod +x /docker-entrypoint-init.d/10-attachra-main-cf.sh
