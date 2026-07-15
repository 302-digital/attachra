# syntax=docker/dockerfile:1

# Postfix image for the Attachra local dev environment, pre-configured to
# hand outgoing mail to the Attachra milter (see main.cf). Based on the
# actively maintained boky/postfix image, which already provides
# Postfix + supervisord for container use and supports post-init hooks
# via /docker-entrypoint-init.d/*.sh (see boky/postfix documentation).
FROM boky/postfix:latest

COPY main.cf /etc/postfix/main.cf.attachra
COPY docker-entrypoint-init.d/10-attachra-main-cf.sh /docker-entrypoint-init.d/10-attachra-main-cf.sh
RUN chmod +x /docker-entrypoint-init.d/10-attachra-main-cf.sh
