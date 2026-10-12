#!/usr/bin/env bash
# backup.sh — backups and restore for the Compose deployment (this directory).
#
#   ./backup.sh                 back up now (run it daily from cron or a systemd timer)
#   ./backup.sh verify          restore the newest backup into a throwaway Postgres
#                               and compare row counts with the running database
#   ./backup.sh restore <dir> --yes
#                               restore a backup over the running stack (stops api,
#                               web and gateway, restores, starts them again)
#
# What one backup holds, under $BACKUP_DIR/<UTC time>/ (directory 0700, files 0600):
#   openctem.dump        pg_dump -Fc of the database, checked with pg_restore --list
#   api-data.tar.gz      the api-data volume: uploaded attachments and evidence
#   gateway-data.tar.gz  the gateway's certificates and internal CA (TLS mode
#                        internal: every sensor trusts that CA; losing it means
#                        re-configuring every sensor)
#   env                  the .env with every secret (APP_ENCRYPTION_KEY decrypts
#                        the stored credentials: a database dump without it is
#                        unusable, and with it the backup is as sensitive as the
#                        database itself)
#   VERSION              OPENCTEM_VERSION of the stack that was backed up
#
# Backups land on this host. They protect against a bad upgrade or deleted data,
# not against losing the host: copy $BACKUP_DIR elsewhere, encrypted (for
# example `age -r <recipient>` or your backup tool's encryption), and run
# `./backup.sh verify` regularly (monthly at least) to prove a restore works.
#
# Settings (environment): BACKUP_DIR (default ./backups), KEEP (number of
# backups kept, default 14), METRICS_TEXTFILE_DIR (node-exporter textfile
# directory; writes openctem_backup.prom for the BackupStale/BackupFailed alerts
# of deploy/observability), COMPOSE_FILE / COMPOSE_PROJECT_NAME as for docker compose.
set -euo pipefail
umask 077

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
dc() { docker compose "$@"; }
project="$(dc config --format json | sed -n 's/^ *"name": *"\([^"]*\)".*/\1/p' | head -1)"
project="${project:-openctem}"

env_get() { # value of a .env variable (no expansion; empty when absent)
	[ -f .env ] || return 0
	sed -n "s/^${1}=\(.*\)$/\1/p" .env | tail -1 | sed -e 's/[[:space:]]*#.*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}
db_name="$(env_get DB_NAME)"
db_name="${db_name:-openctem}"
db_super="$(env_get DB_SUPERUSER)"
[ -n "$db_super" ] || db_super="$(env_get DB_USER)"
db_super="${db_super:-openctem}"

BACKUP_DIR="${BACKUP_DIR:-${here}/backups}"
KEEP="${KEEP:-14}"
HELPER_IMAGE="${HELPER_IMAGE:-$(dc config --images postgres 2>/dev/null | head -1)}"
HELPER_IMAGE="${HELPER_IMAGE:-postgres:17}"

log() { printf '%s backup: %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

metrics() { # metrics <exit code>: the series deploy/observability alerts on
	[ -n "${METRICS_TEXTFILE_DIR:-}" ] || return 0
	local f="${METRICS_TEXTFILE_DIR}/openctem_backup.prom" last=""
	last="$(awk '/^openctem_backup_last_success_timestamp_seconds /{print $2}' "$f" 2>/dev/null || true)"
	[ "$1" = 0 ] && last="$(date +%s)"
	{
		echo "# HELP openctem_backup_last_exit_code Exit code of the last backup run (0 = success)."
		echo "# TYPE openctem_backup_last_exit_code gauge"
		echo "openctem_backup_last_exit_code $1"
		if [ -n "$last" ]; then
			echo "# HELP openctem_backup_last_success_timestamp_seconds Time of the last successful backup."
			echo "# TYPE openctem_backup_last_success_timestamp_seconds gauge"
			echo "openctem_backup_last_success_timestamp_seconds ${last}"
		fi
	} >"${f}.tmp" && chmod 0644 "${f}.tmp" && mv "${f}.tmp" "$f"
}

volume_tar() { # volume_tar <volume> <out.tar.gz>
	docker run --rm --network none -v "${project}_$1:/v:ro" "$HELPER_IMAGE" tar -C /v -czf - . >"$2"
}

do_backup() {
	local ts dir
	ts="$(date -u +%Y%m%dT%H%M%SZ)"
	dir="${BACKUP_DIR}/${ts}"
	mkdir -p "$dir"
	chmod 0700 "$BACKUP_DIR" "$dir"
	trap 'metrics 1; log "FAILED; partial backup left in ${dir}"' ERR

	log "database ${db_name} -> ${dir}/openctem.dump"
	dc exec -T postgres pg_dump -U "$db_super" -d "$db_name" -Fc --no-owner >"${dir}/openctem.dump"
	docker run --rm -i --network none "$HELPER_IMAGE" pg_restore --list <"${dir}/openctem.dump" >/dev/null
	log "volume api-data"
	volume_tar api-data "${dir}/api-data.tar.gz"
	log "volume gateway-data"
	volume_tar gateway-data "${dir}/gateway-data.tar.gz"
	[ -f .env ] && cp .env "${dir}/env"
	env_get OPENCTEM_VERSION >"${dir}/VERSION"
	chmod 0600 "${dir}"/*
	trap - ERR

	# Retention: keep the newest $KEEP backups.
	local n=0 old
	for old in $(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '20*Z' | sort -r); do
		n=$((n + 1))
		[ "$n" -le "$KEEP" ] && continue
		log "retention: removing ${old}"
		find "$old" -mindepth 1 -delete && rmdir "$old"
	done
	metrics 0
	log "OK ${dir} ($(du -sh "$dir" | cut -f1))"
}

newest() { find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '20*Z' | sort | tail -1; }

# Row counts of every table, as "table count" lines, sorted.
count_sql="SELECT format('%s %s', c.relname, (xpath('/row/n/text()', query_to_xml(format('SELECT count(*) AS n FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]::text) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind = 'r' AND n.nspname = 'public' ORDER BY 1"

do_verify() {
	local dir="${1:-$(newest)}"
	[ -n "$dir" ] && [ -s "${dir}/openctem.dump" ] || die "no backup found in ${BACKUP_DIR}"
	name="openctem-restore-check-$$"
	log "restoring ${dir}/openctem.dump into a throwaway Postgres (${name})"
	docker run -d --name "$name" --network none -e POSTGRES_PASSWORD=check -e POSTGRES_DB=check "$HELPER_IMAGE" >/dev/null
	trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
	for _ in $(seq 1 60); do docker exec "$name" pg_isready -U postgres -q 2>/dev/null && break; sleep 1; done
	sleep 2
	docker exec -i "$name" pg_restore -U postgres -d check --no-owner --no-privileges --exit-on-error <"${dir}/openctem.dump"
	docker exec "$name" psql -U postgres -d check -qtAX -c "$count_sql" >"${BACKUP_DIR}/.verify-restored"
	dc exec -T postgres psql -U "$db_super" -d "$db_name" -qtAX -c "$count_sql" >"${BACKUP_DIR}/.verify-live"
	local tables
	tables="$(wc -l <"${BACKUP_DIR}/.verify-restored")"
	[ "$tables" -gt 0 ] || die "the restored database has no tables"
	# Rows written since the backup make live counts differ; report, do not fail.
	if diff -q "${BACKUP_DIR}/.verify-live" "${BACKUP_DIR}/.verify-restored" >/dev/null; then
		log "verify OK: ${tables} tables restored, every row count equals the running database"
	else
		log "verify OK: ${tables} tables restored; row counts that differ from the running database (changes since the backup):"
		{ diff "${BACKUP_DIR}/.verify-live" "${BACKUP_DIR}/.verify-restored" || true; } | sed -n 's/^[<>] /  /p' | head -40
	fi
	for v in api-data gateway-data; do
		gzip -t "${dir}/${v}.tar.gz" || die "${v}.tar.gz is corrupt"
	done
	log "volume archives OK"
	find "${BACKUP_DIR}/.verify-restored" "${BACKUP_DIR}/.verify-live" -delete
}

do_restore() {
	local dir="$1"
	[ "${2:-}" = "--yes" ] || die "restore replaces the database and volumes of the running stack; rerun with --yes"
	[ -s "${dir}/openctem.dump" ] || die "${dir} is not a backup"
	if [ -f "${dir}/VERSION" ] && [ "$(cat "${dir}/VERSION")" != "$(env_get OPENCTEM_VERSION)" ]; then
		log "WARNING: the backup was taken on $(cat "${dir}/VERSION"); the stack runs $(env_get OPENCTEM_VERSION)."
		log "         Restore with the backup's OPENCTEM_VERSION, then upgrade (migrations run on start)."
	fi
	log "stopping gateway, web, api"
	dc stop gateway web api
	log "restoring the database"
	dc exec -T postgres psql -U "$db_super" -d postgres -v ON_ERROR_STOP=1 -qX \
		-c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${db_name}' AND pid <> pg_backend_pid()" >/dev/null
	dc exec -T postgres pg_restore -U "$db_super" -d "$db_name" --clean --if-exists --no-owner --exit-on-error <"${dir}/openctem.dump"
	# The least-privilege roles (db-roles) re-grant on the restored schema.
	dc up -d --no-deps db-roles >/dev/null
	for v in api-data gateway-data; do
		log "restoring volume ${v}"
		docker run --rm -i --network none -v "${project}_${v}:/v" "$HELPER_IMAGE" \
			sh -c 'find /v -mindepth 1 -delete && tar -C /v -xzf -' <"${dir}/${v}.tar.gz"
	done
	log "starting the stack"
	dc up -d
	log "restore done; check: docker compose ps, and log in"
}

case "${1:-backup}" in
	backup) do_backup ;;
	verify) do_verify "${2:-}" ;;
	restore) [ -n "${2:-}" ] || die "usage: $0 restore <backup dir> --yes"; do_restore "$2" "${3:-}" ;;
	*) die "usage: $0 [backup | verify [dir] | restore <dir> --yes]" ;;
esac
