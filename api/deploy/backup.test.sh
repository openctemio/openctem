#!/usr/bin/env bash
# Tests for backup.sh with a stub docker and a stub age (no containers, no real keys).
# Run: bash api/deploy/backup.test.sh
set -euo pipefail
src="$(cd "$(dirname "$0")" && pwd)/backup.sh"
pass=0 failed=0
ok() { echo "ok:   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; failed=$((failed + 1)); }

# fixture: a copy of backup.sh next to a stub bin dir; prints the work dir.
fixture() {
	local d
	d="$(mktemp -d)"
	mkdir -p "$d/bin" "$d/deploy"
	cp "$src" "$d/deploy/backup.sh"
	printf 'DB_NAME=openctem\nOPENCTEM_VERSION=v9\nAPP_ENCRYPTION_KEY=secretsecret\n' >"$d/deploy/.env"
	cat >"$d/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
compose)
	case "$2" in
	config) if [ "${3:-}" = "--images" ]; then echo postgres:17; else echo '  "name": "stubproj",'; fi ;;
	exec) case "$*" in *psql*) echo "t 1" ;; *) echo "PLAINTEXT-DUMP" ;; esac ;;
	esac ;;
exec) case "$*" in *pg_restore*) cat >/dev/null ;; *psql*) echo "t 1" ;; esac ;;
rm) ;;
volume) [ "$3" = "stubproj_signer-state" ] && [ -n "${WITH_SIGNER:-}" ] || { [ "$3" = "stubproj_signer-keys" ] && [ -n "${WITH_SIGNER:-}" ]; } ;;
run)
	case "$*" in
	*-d\ --name*) ;;
	*pg_restore*) cat >/dev/null ;;
	*tar*)
		[ -z "${FAIL_VOLUME:-}" ] || { echo boom >&2; exit 1; }
		echo "PLAINTEXT-TAR" | gzip ;;
	esac ;;
esac
STUB
	cat >"$d/bin/age" <<'STUB'
#!/usr/bin/env bash
case "$1" in
-d) shift; [ "$1" = -i ] && shift 2; base64 -d <"$1" ;;
*) base64 ;;
esac
STUB
	chmod +x "$d/bin/docker" "$d/bin/age"
	echo "$d"
}
run_backup() { # run_backup <fixture> [env assignments...]; prints rc
	local d="$1"
	shift
	(cd "$d/deploy" && env PATH="$d/bin:$PATH" BACKUP_DIR="$d/backups" BACKUP_STATUS_DIR="$d/status" "$@" bash ./backup.sh backup >"$d/out" 2>&1) && echo 0 || echo $?
}

# 1. with a recipient: every file is .age, no plaintext remains, env is its own archive.
d="$(fixture)"
rc="$(run_backup "$d" WITH_SIGNER=1 BACKUP_AGE_RECIPIENT=age1testrecipient)"
b="$(find "$d/backups" -mindepth 1 -maxdepth 1 -type d | head -1)"
[ "$rc" = 0 ] || bad "recipient run failed ($rc): $(tail -3 "$d/out")"
plain="$(find "$b" -type f ! -name '*.age' ! -name VERSION | wc -l)"
[ "$plain" = 0 ] && ok "recipient: no plaintext file remains" || bad "recipient: $plain plaintext files"
for f in openctem.dump api-data.tar.gz gateway-data.tar.gz signer-keys.tar.gz signer-state.tar.gz env.tar.gz; do
	[ -s "$b/$f.age" ] || bad "recipient: $f.age missing"
done
! grep -rq 'secretsecret\|PLAINTEXT' "$b" && ok "recipient: no secret in the backup directory" || bad "recipient: plaintext content found"
! grep -q 'WARNING' "$d/out" && ok "recipient: no plaintext warning" || bad "recipient: unexpected warning"

# 2. without a recipient: loud warning, plaintext files.
d="$(fixture)"
rc="$(run_backup "$d")"
b="$(find "$d/backups" -mindepth 1 -maxdepth 1 -type d | head -1)"
[ "$rc" = 0 ] || bad "plain run failed ($rc)"
grep -q 'WARNING: BACKUP_AGE_RECIPIENT is not set' "$d/out" && ok "no recipient: warning printed" || bad "no recipient: no warning"
[ -s "$b/openctem.dump" ] && [ -s "$b/env.tar.gz" ] && [ ! -e "$b/signer-keys.tar.gz" ] && ok "no recipient: plaintext files, signer volumes skipped when absent" || bad "no recipient: unexpected layout"

# 3. a failure inside volume_tar writes exit code 1 to the status file.
d="$(fixture)"
rc="$(run_backup "$d" FAIL_VOLUME=1)"
[ "$rc" != 0 ] || bad "failing volume: script exited 0"
grep -q '^openctem_backup_last_exit_code 1$' "$d/status/openctem_backup.prom" 2>/dev/null && ok "volume_tar failure records exit code 1" || bad "volume_tar failure not recorded"

# 4. a failure with a recipient leaves no plaintext behind.
d="$(fixture)"
rc="$(run_backup "$d" FAIL_VOLUME=1 BACKUP_AGE_RECIPIENT=age1testrecipient)"
plain="$(find "$d/backups" -type f ! -name '*.age' ! -name VERSION | wc -l)"
[ "$plain" = 0 ] && ok "failed encrypted run leaves no plaintext" || bad "failed encrypted run left $plain plaintext files"

# 5. verify decrypts with BACKUP_AGE_IDENTITY and refuses without it.
d="$(fixture)"
run_backup "$d" BACKUP_AGE_RECIPIENT=age1testrecipient >/dev/null
: >"$d/id.txt"
rc=0; (cd "$d/deploy" && env PATH="$d/bin:$PATH" BACKUP_DIR="$d/backups" bash ./backup.sh verify >"$d/vout" 2>&1) || rc=$?
[ "$rc" != 0 ] && grep -q 'BACKUP_AGE_IDENTITY' "$d/vout" && ok "verify refuses an encrypted backup without an identity" || bad "verify without identity: rc=$rc"
rc=0; (cd "$d/deploy" && env PATH="$d/bin:$PATH" BACKUP_DIR="$d/backups" BACKUP_AGE_IDENTITY="$d/id.txt" bash ./backup.sh verify >"$d/vout" 2>&1) || true
grep -q 'volume archives OK' "$d/vout" && ok "verify decrypts with the identity" || bad "verify with identity: $(tail -3 "$d/vout")"

echo "passed: $pass failed: $failed"
[ "$failed" = 0 ]
