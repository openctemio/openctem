# PostgreSQL with pgBackRest, for the off-host backup overlay
# (../docker-compose.backup.yml). Built on the same PostgreSQL image the stack
# already runs: the Debian image (default) or the Alpine one (POSTGRES_IMAGE=
# postgres:17-alpine). Keep the flavour of the existing data directory: switching
# between them changes the C library and with it text sort order, which can
# corrupt indexes.
ARG POSTGRES_IMAGE=postgres:17
FROM ${POSTGRES_IMAGE}
RUN if command -v apk > /dev/null; then \
        apk add --no-cache bash pgbackrest; \
    else \
        apt-get update && apt-get install -y --no-install-recommends pgbackrest && rm -rf /var/lib/apt/lists/*; \
    fi \
    && pgbackrest version
COPY render-conf.sh pg-entrypoint.sh backup-entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/render-conf.sh /usr/local/bin/pg-entrypoint.sh /usr/local/bin/backup-entrypoint.sh
