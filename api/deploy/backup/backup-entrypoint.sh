#!/bin/bash
# The backup service: creates the stanza, takes a first full backup, then a
# differential backup every day and a full one on BACKUP_FULL_DAY (0=Sunday),
# at BACKUP_TIME (UTC, HH:MM). Also: "restore <pgbackrest restore options>"
# (the database must be stopped) and any other pgbackrest command via "pgbackrest ...".
set -Eeuo pipefail
. /usr/local/bin/render-conf.sh
render_conf
stanza="${BACKUP_STANZA:-openctem}"
pgb() { gosu postgres pgbackrest --stanza="$stanza" "$@"; }
log() { echo "$(date -u +%FT%TZ) backup: $*"; }

case "${1:-scheduler}" in
restore)
	shift
	[ ! -e /var/lib/postgresql/data/postmaster.pid ] || bfail "the database is running: stop it first (docker compose stop postgres)"
	install -d -m 0700 -o postgres -g postgres /var/lib/postgresql/data
	exec gosu postgres pgbackrest --stanza="$stanza" restore "$@"
	;;
pgbackrest)
	shift
	exec gosu postgres pgbackrest --stanza="$stanza" "$@"
	;;
scheduler) ;;
*) bfail "unknown command '$1' (scheduler, restore, pgbackrest)" ;;
esac

at="${BACKUP_TIME:-02:30}"
[[ "$at" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || bfail "BACKUP_TIME must be HH:MM (UTC), got '$at'"
fullday="$(num BACKUP_FULL_DAY 0 0)"
[ "$fullday" -le 6 ] || bfail "BACKUP_FULL_DAY must be 0-6"

# Ready when the repository exists and archiving works end to end (check). This
# also waits out the database's first start, when it restarts once after initdb.
until pg_isready -q -h /var/run/postgresql && pgb stanza-create && pgb check; do
	log "not ready (database starting, or the repository cannot be reached): retrying in 15 s"
	sleep 15
done
if ! pgb info 2> /dev/null | grep -q 'full backup:'; then
	log "no backup yet: taking the first full backup"
	pgb backup --type=full || log "ERROR: first full backup failed"
fi

while true; do
	now=$(date -u +%s)
	next=$(date -u -d "$(date -u +%F) $at:00" +%s)
	[ "$next" -gt "$now" ] || next=$((next + 86400))
	log "next backup at $(date -u -d "@$next" +%FT%TZ)"
	sleep "$((next - now))"
	type=diff
	[ "$(date -u +%w)" != "$fullday" ] || type=full
	log "starting $type backup"
	if pgb backup --type="$type"; then
		log "$type backup ok"
	else
		log "ERROR: $type backup failed"
	fi
	if [ "$type" = full ]; then pgb verify || log "ERROR: verify reported problems"; fi
done
