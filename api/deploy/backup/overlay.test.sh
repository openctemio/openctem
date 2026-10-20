#!/usr/bin/env bash
# Tests for the backup overlay without containers: the generated pgBackRest
# configuration for each target, the refusals, and `docker compose config` for
# every target variant when docker is available.
# Run: bash api/deploy/backup/overlay.test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pass=0 failed=0
ok() { echo "ok:   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; failed=$((failed + 1)); }
tmp="$(mktemp -d)"
trap 'find "$tmp" -delete' EXIT

# render <name> VAR=value ...: render the configuration in a subshell with a
# stubbed install/chown (no root, no postgres user); prints the file on success.
render() {
	local name="$1"
	shift
	local d="$tmp/$name"
	mkdir -p "$d/sec" "$d/conf"
	(
		env -i PATH="$PATH" BACKUP_SECRETS_DIR_IN_CONTAINER="$d/sec" BACKUP_CONF_DIR="$d/conf" \
			BACKUP_SPOOL_DIR="$d/spool" BACKUP_LOG_DIR="$d/log" "$@" bash -c '
			install() { # only the forms render-conf.sh uses
				if [ "$1" = -d ]; then shift; while [ "${1:-}" = -m ] || [ "${1:-}" = -o ] || [ "${1:-}" = -g ]; do shift 2; done; mkdir -p "$@"
				else while [ "$1" = -m ] || [ "$1" = -o ] || [ "$1" = -g ]; do shift 2; done; cp "$1" "$2"; fi
			}
			chown() { :; }
			. '"$here"'/render-conf.sh
			render_conf
		' > "$d/out" 2>&1
	) && cat "$d/conf/pgbackrest.conf"
}
secrets() { # secrets <name>: the cipher passphrase plus s3/sftp material
	local d="$tmp/$1/sec"
	mkdir -p "$d"
	printf '%s' 'abcdefghijklmnopqrstuvwxyz012345' > "$d/cipher_pass"
	printf '%s' 'AKIAEXAMPLE' > "$d/s3_access_key"
	printf '%s' 'secretexample' > "$d/s3_secret_key"
	printf '%s' 'PRIVATE-KEY-PLACEHOLDER' > "$d/sftp_private_key"
}
fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

secrets s3
out="$(render s3 BACKUP_TARGET=s3 BACKUP_S3_ENDPOINT=x.r2.example BACKUP_S3_BUCKET=b BACKUP_S3_REGION=auto BACKUP_S3_URI_STYLE=path)"
for want in repo1-type=s3 repo1-s3-bucket=b repo1-s3-uri-style=path repo1-s3-key=AKIAEXAMPLE repo1-cipher-type=aes-256-cbc \
	repo1-retention-full=4 repo1-retention-diff=7 pg1-socket-path=/var/run/postgresql archive-async=y; do
	grep -qx "$want" <<< "$out" && ok "s3 has $want" || bad "s3 lacks $want"
done

secrets sftp
out="$(render sftp BACKUP_TARGET=sftp BACKUP_SFTP_HOST=h BACKUP_SFTP_USER=u BACKUP_SFTP_PATH=/srv/b BACKUP_SFTP_HOST_FINGERPRINT=$fp)"
for want in repo1-type=sftp repo1-sftp-host=h repo1-sftp-host-key-check-type=fingerprint repo1-sftp-host-fingerprint=$fp; do
	grep -qx "$want" <<< "$out" && ok "sftp has $want" || bad "sftp lacks $want"
done
render sftp-nofp BACKUP_TARGET=sftp BACKUP_SFTP_HOST=h BACKUP_SFTP_USER=u BACKUP_SFTP_PATH=/p > /dev/null && bad "sftp without a host fingerprint was accepted" || ok "sftp without a host fingerprint is refused"
secrets sftp-badfp
render sftp-badfp BACKUP_TARGET=sftp BACKUP_SFTP_HOST=h BACKUP_SFTP_USER=u BACKUP_SFTP_PATH=/p BACKUP_SFTP_HOST_FINGERPRINT=zz > /dev/null && bad "a malformed fingerprint was accepted" || ok "a malformed fingerprint is refused"

secrets local
out="$(render local BACKUP_TARGET=local BACKUP_RETENTION_FULL=2)"
grep -qx 'repo1-type=posix' <<< "$out" && grep -qx 'repo1-retention-full=2' <<< "$out" && ok "local target and retention" || bad "local target"

secrets none
render none BACKUP_TARGET=none > /dev/null && bad "target none was accepted" || ok "target none is refused"
render unset > /dev/null && bad "an unset target was accepted" || ok "an unset target is refused"
secrets inj
render inj BACKUP_TARGET=s3 BACKUP_S3_ENDPOINT=x BACKUP_S3_BUCKET='b
[evil]' > /dev/null && bad "a newline in a setting was accepted" || ok "a setting that could add an INI line is refused"
secrets nokey
find "$tmp/nokey/sec/s3_access_key" -delete
render nokey BACKUP_TARGET=s3 BACKUP_S3_ENDPOINT=x BACKUP_S3_BUCKET=b > /dev/null && bad "a missing s3 access key file was accepted" || ok "a missing s3 access key file is refused"
secrets shortkey
printf 'short' > "$tmp/shortkey/sec/cipher_pass"
render shortkey BACKUP_TARGET=local > /dev/null && bad "a short passphrase was accepted" || ok "a short cipher passphrase is refused"
mkdir -p "$tmp/nosec/sec"
render nosec BACKUP_TARGET=local > /dev/null && bad "a missing passphrase file was accepted" || ok "a missing cipher passphrase file is refused"
secrets badret
render badret BACKUP_TARGET=local BACKUP_RETENTION_FULL=0 > /dev/null && bad "retention 0 was accepted" || ok "retention 0 full backups is refused"

# The rendered file must not be world readable in the real container: render-conf.sh sets umask 027 and mode 0640.
grep -q 'chmod 0640 "$conf"' "$here/render-conf.sh" && ok "conf mode is 0640" || bad "conf mode"

# Compose: every target variant validates, and the base stack has no backup service.
if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then
	deploy="$(cd "$here/.." && pwd)"
	envf="$tmp/env"
	cp "$deploy/.env.example" "$envf"
	[ -z "$(docker compose --env-file "$envf" -f "$deploy/docker-compose.yml" config --services 2> /dev/null | grep -x backup)" ] \
		&& ok "base compose has no backup service" || bad "base compose has a backup service"
	for t in s3 sftp local; do
		BACKUP_TARGET=$t docker compose --env-file "$envf" -f "$deploy/docker-compose.yml" -f "$deploy/docker-compose.backup.yml" config -q 2> "$tmp/err" \
			&& ok "compose config with the overlay, target $t" || { bad "compose config target $t"; cat "$tmp/err"; }
	done
	docker compose --env-file "$envf" -f "$deploy/docker-compose.yml" -f "$deploy/docker-compose.backup.yml" config -q 2> /dev/null \
		&& bad "the overlay without BACKUP_TARGET was accepted" || ok "the overlay without BACKUP_TARGET is refused"
	cfg="$(BACKUP_TARGET=s3 docker compose --env-file "$envf" -f "$deploy/docker-compose.yml" -f "$deploy/docker-compose.backup.yml" config 2> /dev/null)"
	grep -q 'cipher-pass\|BACKUP_CIPHER' <<< "$cfg" && bad "a secret appears in the compose config" || ok "no secret in the compose config"
else
	echo "skip: docker compose not available"
fi
echo "$pass passed, $failed failed"
[ "$failed" -eq 0 ]
