#!/bin/bash
# Entrypoint of the postgres service in the backup overlay: renders the
# pgBackRest configuration, then starts the stock PostgreSQL entrypoint with
# archiving switched on (archive_mode needs this restart once).
set -Eeuo pipefail
. /usr/local/bin/render-conf.sh
render_conf
stanza="${BACKUP_STANZA:-openctem}"
args=("$@")
timeout="$(num BACKUP_ARCHIVE_TIMEOUT 300 30)"
if [ "${1:-}" = postgres ]; then
	args+=(-c archive_mode=on
		-c "archive_command=pgbackrest --stanza=$stanza archive-push %p"
		-c "archive_timeout=$timeout")
fi
exec docker-entrypoint.sh "${args[@]}"
