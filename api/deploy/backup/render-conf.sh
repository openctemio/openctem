#!/bin/bash
# Writes /etc/pgbackrest/pgbackrest.conf from the BACKUP_* settings and the
# secret files under /run/backup-secrets (read as root, written to a tmpfs that
# only root and the postgres group can read). Sourced by both entrypoints.
set -Eeuo pipefail
umask 027

sec="${BACKUP_SECRETS_DIR_IN_CONTAINER:-/run/backup-secrets}"
conf_dir="${BACKUP_CONF_DIR:-/etc/pgbackrest}"
conf="$conf_dir/pgbackrest.conf"
stanza="${BACKUP_STANZA:-openctem}"

bfail() { echo "backup: $*" >&2; exit 1; }

secret() { # secret <file name>: the single-line content of a secret file
	local f="$sec/$1" v
	[ -r "$f" ] || bfail "missing secret file $f (see docs/deployment/backup-and-restore.md)"
	v="$(<"$f")"
	[ -n "$v" ] || bfail "secret file $f is empty"
	case "$v" in *$'\n'*) bfail "secret file $f must hold one line" ;; esac
	printf '%s' "$v"
}

num() { # num <name> <default> [min]: a positive integer setting
	local v="${!1:-$2}"
	[[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "${3:-1}" ] || bfail "$1 must be an integer >= ${3:-1}, got '$v'"
	printf '%s' "$v"
}

# Settings go into an INI file: refuse anything that could add a line or section.
plain() { # plain <name> <value>
	case "$2" in *$'\n'*|*'['*|*']'*|*'#'*|*' '*) bfail "$1 holds a character that is not allowed (space, [, ], #, newline)" ;; esac
	printf '%s' "$2"
}

render_conf() {
	local target="${BACKUP_TARGET:-none}"
	case "$target" in
	s3 | sftp | local) ;;
	none) bfail "BACKUP_TARGET=none: do not include docker-compose.backup.yml, or set BACKUP_TARGET to s3, sftp or local" ;;
	*) bfail "BACKUP_TARGET must be s3, sftp or local, got '$target'" ;;
	esac
	local pass full diff pmax
	pass="$(secret cipher_pass)"
	[ "${#pass}" -ge 24 ] || bfail "cipher_pass must be at least 24 characters (openssl rand -base64 32)"
	full="$(num BACKUP_RETENTION_FULL 4)"
	diff="$(num BACKUP_RETENTION_DIFF 7 0)"
	pmax="$(num BACKUP_PROCESS_MAX 2)"
	# Read and check every value before the file is written. Each one is a plain
	# assignment so that a refusal stops the script (inside echo "$(...)" it would not).
	local s3_path s3_bucket s3_endpoint s3_region s3_style s3_key s3_secret s3_ca=""
	local sftp_path sftp_host sftp_port sftp_user sftp_fp sftp_pp=""
	case "$target" in
	s3)
		s3_path="$(plain BACKUP_S3_PATH "${BACKUP_S3_PATH:-openctem}")"
		s3_bucket="$(plain BACKUP_S3_BUCKET "${BACKUP_S3_BUCKET:?BACKUP_S3_BUCKET is required for target s3}")"
		s3_endpoint="$(plain BACKUP_S3_ENDPOINT "${BACKUP_S3_ENDPOINT:?BACKUP_S3_ENDPOINT is required for target s3}")"
		s3_region="$(plain BACKUP_S3_REGION "${BACKUP_S3_REGION:-us-east-1}")"
		s3_style="$(plain BACKUP_S3_URI_STYLE "${BACKUP_S3_URI_STYLE:-host}")"
		[ "$s3_style" = host ] || [ "$s3_style" = path ] || bfail "BACKUP_S3_URI_STYLE must be host or path"
		s3_key="$(secret s3_access_key)"
		s3_secret="$(secret s3_secret_key)"
		if [ -f "$sec/s3_ca.pem" ]; then
			install -d -m 0750 -o root -g postgres "$conf_dir"
			install -m 0640 -o root -g postgres "$sec/s3_ca.pem" "$conf_dir/s3_ca.pem"
			s3_ca=1
		fi
		;;
	sftp)
		sftp_fp="$(plain BACKUP_SFTP_HOST_FINGERPRINT "${BACKUP_SFTP_HOST_FINGERPRINT:?BACKUP_SFTP_HOST_FINGERPRINT (hex sha256 of the host key) is required for target sftp}")"
		[[ "$sftp_fp" =~ ^[0-9a-fA-F]{64}$ ]] || bfail "BACKUP_SFTP_HOST_FINGERPRINT must be 64 hex characters (sha256 of the host key, see the docs)"
		[ -r "$sec/sftp_private_key" ] || bfail "missing secret file $sec/sftp_private_key"
		sftp_path="$(plain BACKUP_SFTP_PATH "${BACKUP_SFTP_PATH:?BACKUP_SFTP_PATH is required for target sftp}")"
		sftp_host="$(plain BACKUP_SFTP_HOST "${BACKUP_SFTP_HOST:?BACKUP_SFTP_HOST is required for target sftp}")"
		sftp_port="$(num BACKUP_SFTP_PORT 22)"
		sftp_user="$(plain BACKUP_SFTP_USER "${BACKUP_SFTP_USER:?BACKUP_SFTP_USER is required for target sftp}")"
		if [ -r "$sec/sftp_key_passphrase" ]; then sftp_pp="$(secret sftp_key_passphrase)"; fi
		install -d -m 0750 -o root -g postgres "$conf_dir"
		install -m 0640 -o root -g postgres "$sec/sftp_private_key" "$conf_dir/sftp_key"
		;;
	esac
	install -d -m 0750 -o root -g postgres "$conf_dir"
	{
		echo "[global]"
		echo "repo1-cipher-type=aes-256-cbc"
		echo "repo1-cipher-pass=$pass"
		echo "repo1-retention-full-type=count"
		echo "repo1-retention-full=$full"
		echo "repo1-retention-diff=$diff"
		echo "process-max=$pmax"
		echo "compress-type=zst"
		echo "archive-async=y"
		echo "spool-path=/var/spool/pgbackrest"
		echo "start-fast=y"
		echo "log-path=/var/log/pgbackrest"
		echo "log-level-console=info"
		echo "log-level-file=warn"
		case "$target" in
		s3)
			echo "repo1-type=s3"
			echo "repo1-path=/$s3_path"
			echo "repo1-s3-bucket=$s3_bucket"
			echo "repo1-s3-endpoint=$s3_endpoint"
			echo "repo1-s3-region=$s3_region"
			echo "repo1-s3-uri-style=$s3_style"
			echo "repo1-s3-key=$s3_key"
			echo "repo1-s3-key-secret=$s3_secret"
			[ -z "$s3_ca" ] || echo "repo1-storage-ca-file=$conf_dir/s3_ca.pem"
			[ "${BACKUP_S3_VERIFY_TLS:-y}" = y ] || echo "repo1-storage-verify-tls=n"
			;;
		sftp)
			echo "repo1-type=sftp"
			echo "repo1-path=$sftp_path"
			echo "repo1-sftp-host=$sftp_host"
			echo "repo1-sftp-host-port=$sftp_port"
			echo "repo1-sftp-host-user=$sftp_user"
			echo "repo1-sftp-host-key-hash-type=sha256"
			echo "repo1-sftp-host-key-check-type=fingerprint"
			echo "repo1-sftp-host-fingerprint=$sftp_fp"
			echo "repo1-sftp-private-key-file=$conf_dir/sftp_key"
			[ -z "$sftp_pp" ] || echo "repo1-sftp-private-key-passphrase=$sftp_pp"
			;;
		local)
			echo "repo1-type=posix"
			echo "repo1-path=/backup-repo"
			;;
		esac
		echo
		echo "[$stanza]"
		echo "pg1-path=/var/lib/postgresql/data"
		echo "pg1-socket-path=/var/run/postgresql"
		echo "pg1-user=${DB_SUPERUSER:-openctem}"
	} > "$conf"
	chown root:postgres "$conf"
	chmod 0640 "$conf"
	install -d -m 0750 -o postgres -g postgres "${BACKUP_SPOOL_DIR:-/var/spool/pgbackrest}" "${BACKUP_LOG_DIR:-/var/log/pgbackrest}"
}
