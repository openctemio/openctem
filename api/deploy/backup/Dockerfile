# PostgreSQL with pgBackRest, for the off-host backup overlay
# (../docker-compose.backup.yml). The PostgreSQL image's own package source
# carries pgBackRest, so the version follows the PostgreSQL release.
ARG POSTGRES_VERSION=17
FROM postgres:${POSTGRES_VERSION}
RUN apt-get update \
    && apt-get install -y --no-install-recommends pgbackrest \
    && rm -rf /var/lib/apt/lists/* \
    && pgbackrest version
COPY render-conf.sh pg-entrypoint.sh backup-entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/render-conf.sh /usr/local/bin/pg-entrypoint.sh /usr/local/bin/backup-entrypoint.sh
