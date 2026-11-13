#!/usr/bin/env bash
# Tests for install.sh, setup.sh and lib/common.sh with a stub docker and stub
# host tools (no containers, no network, no real keys).
# Run: bash server/deploy/install.test.sh
set -euo pipefail
src="$(cd "$(dirname "$0")" && pwd)"
pass=0 failed=0
ok() { echo "ok:   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; failed=$((failed + 1)); }
check() { # check <description> <command...>
	local d="$1"
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
}

DIGEST="sha256:$(printf 'a%.0s' $(seq 1 64))"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# fixture: a copy of the deploy files next to a stub bin dir; prints the dir.
fixture() {
	local d
	d="$(mktemp -d "$root/f.XXXXXX")"
	mkdir -p "$d/bin" "$d/deploy"
	cp -R "$src/lib" "$src/sensor" "$d/deploy/"
	cp "$src/install.sh" "$src/setup.sh" "$src/.env.example" "$src"/docker-compose*.yml "$d/deploy/"
	cat >"$d/bin/docker" <<'STUB'
#!/usr/bin/env bash
# Every call is logged; compose calls with the COMPOSE_FILE of ./.env.
cf="$(sed -n 's/^COMPOSE_FILE=//p' .env 2>/dev/null | tail -n 1)"
echo "$* [COMPOSE_FILE=$cf]" >>"$STUB_LOG"
digest="$STUB_DIGEST"
case "$1" in
version) echo "${STUB_ENGINE:-27.3.1}" ;;
info) echo "$STUB_ROOT" ;;
ps)
	case "$*" in
	*working_dir*) [ -n "${STUB_PS_DIR:-}" ] && echo "$STUB_PS_DIR" ;;
	*config_files*) [ -n "${STUB_PS_FILES:-}" ] && echo "$STUB_PS_FILES" ;;
	*) [ -n "${STUB_PS_DIR:-}" ] && echo 0123456789ab ;;
	esac
	exit 0 ;;
network) exit 0 ;;
image)
	ref="${*: -1}"
	[ -n "${STUB_MOVED:-}" ] && digest="sha256:$(printf 'b%.0s' $(seq 1 64))"
	echo "${ref%:*}@$digest" ;;
run)
	[ -n "${STUB_BAD_SIG:-}" ] && { echo "no matching signatures" >&2; exit 1; }
	for a in "$@"; do case "$a" in ghcr.io/openctemio/*) ref="$a" ;; esac; done
	printf '[{"critical":{"identity":{"docker-reference":"%s"},"image":{"docker-manifest-digest":"%s"}}}]\n' "$ref" "$digest" ;;
compose)
	shift
	case "$1" in
	version) echo "${STUB_COMPOSE:-2.29.7}" ;;
	config)
		v="$(sed -n 's/^OPENCTEM_VERSION=//p' .env)"
		api="$(sed -n 's/^API_IMAGE=//p' .env)"
		for i in "${api:-ghcr.io/openctemio/openctem-api}" ghcr.io/openctemio/openctem-web ghcr.io/openctemio/openctem-console \
			ghcr.io/openctemio/openctem-gateway ghcr.io/openctemio/migrations; do echo "$i:$v"; done
		echo postgres:17
		echo redis:7-alpine
		case "$cf" in *sensor*) echo ghcr.io/openctemio/sensor:v0.41.0 ;; esac ;;
	pull | up) ;;
	ps)
		case "$*" in
		*gateway*) echo "gateway healthy" ;;
		*sensor*) echo running ;;
		*\ api) [ -n "${STUB_API_RUNNING:-}" ] && echo running ;;
		esac
		exit 0 ;;
	logs) echo "Enrolled: shared sensor bundled-sensor" ;;
	run)
		case "$*" in
		*check-config*)
			case "${STUB_CHECK:-}" in
			invalid) echo "configuration INVALID: REDIS_PASSWORD too short" >&2; exit 1 ;;
			docker) echo "Error response from daemon: failed to set up container networking: Address already in use" >&2; exit 1 ;;
			esac
			echo "configuration valid: APP_ENV=production AUTH_PROVIDER=local SIGNUP_MODE=disabled" ;;
		*bootstrap-admin*) echo "Temporary password: TEMPSECRET-0123456789" ;;
		esac ;;
	esac ;;
esac
STUB
	cat >"$d/bin/ss" <<'STUB'
#!/usr/bin/env bash
case "$*" in *":${STUB_BUSY_PORT:-none}"*) echo "LISTEN 0 4096 0.0.0.0:${STUB_BUSY_PORT} 0.0.0.0:*" ;; esac
STUB
	cat >"$d/bin/curl" <<'STUB'
#!/usr/bin/env bash
case "$*" in *-sSI*) printf 'HTTP/2 401\r\ndate: %s\r\n' "$(date -u -R)" ;; *) printf 200 ;; esac
STUB
	printf '#!/usr/bin/env bash\necho "Filesystem 1024-blocks Used Available Capacity Mounted"\necho "/dev/x 1 1 104857600 1%% /"\n' >"$d/bin/df"
	# shellcheck disable=SC2016 # $2 belongs to the stub
	printf '#!/usr/bin/env bash\necho "127.0.0.1 $2"\n' >"$d/bin/getent"
	printf '#!/usr/bin/env bash\necho yes\n' >"$d/bin/timedatectl"
	printf '#!/usr/bin/env bash\nexit 0\n' >"$d/bin/sleep"
	chmod +x "$d/bin/"*
	echo "$d"
}

# run_install <fixture> [args...]: no terminal on stdin; prints rc.
run_install() {
	local d="$1"
	shift
	(env PATH="$d/bin:$PATH" STUB_LOG="$d/log" STUB_ROOT="$d" STUB_DIGEST="$DIGEST" \
		bash "$d/deploy/install.sh" "$@" </dev/null >"$d/out" 2>&1) && echo 0 || echo $?
}

full_args=(--yes --host ctem.example.com --version v9.9.9 --admin-email admin@example.com
	--backup-admin-email breakglass@example.com)

# 1. --help and an unknown option.
d="$(fixture)"
check "--help exits 0 with the usage" bash -c "bash '$d/deploy/install.sh' --help >'$d/out' 2>&1 && grep -q -- --credentials-file '$d/out'"
rc="$(run_install "$d" --bogus)"
check "an unknown option fails" [ "$rc" != 0 ]

# 2. No terminal and no host: fails, writes nothing, starts nothing.
rc="$(run_install "$d" --yes --version v9.9.9)"
check "no terminal, no host: fails" [ "$rc" != 0 ]
check "no terminal, no host: names the option" grep -q -- "--host" "$d/out"
check "no terminal, no host: no .env written" [ ! -e "$d/deploy/.env" ]
check "no terminal, no host: nothing started" bash -c "! grep -q 'compose up' '$d/log' 2>/dev/null"

# 3. An administrator without a terminal needs a credentials file, before anything is written.
rc="$(run_install "$d" "${full_args[@]}")"
check "no terminal, admin without --credentials-file: fails" [ "$rc" != 0 ]
check "no terminal, admin: says how" grep -q -- "--credentials-file" "$d/out"
check "no terminal, admin: no .env written" [ ! -e "$d/deploy/.env" ]

# 4. The full non-interactive install.
rm -f "$d/log"
rc="$(run_install "$d" "${full_args[@]}" --credentials-file "$d/first-admin.txt")"
check "full install: exit 0" [ "$rc" = 0 ] || cat "$d/out"
check ".env is mode 0600" [ "$(stat -c %a "$d/deploy/.env")" = 600 ]
check "COMPOSE_FILE recorded with the sensor overlay (DNS name)" grep -qx "COMPOSE_FILE=docker-compose.yml:docker-compose.sensor.yml" "$d/deploy/.env"
check "every compose call saw that COMPOSE_FILE" bash -c "! grep '^compose' '$d/log' | grep -v '^compose version' | grep -v 'COMPOSE_FILE=docker-compose.yml:docker-compose.sensor.yml\]' | grep -q ."
check "signatures verified before the pull" bash -c "grep -n 'cosign\|^run' '$d/log' | head -n 1 | grep -q '^[0-9]*:run' && [ \$(grep -n '^run' '$d/log' | tail -n 1 | cut -d: -f1) -lt \$(grep -n '^compose pull' '$d/log' | cut -d: -f1) ]"
check "every release image verified, sensor included" bash -c "[ \$(grep -c '^run .* verify ghcr.io/openctemio/' '$d/log') = 6 ]"
check "the sensor is checked against the sensor release identity" grep -q "verify ghcr.io/openctemio/sensor:v0.41.0 --certificate-identity https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml@refs/tags/v0.41.0" "$d/log"
check "the configuration check ran before up" bash -c "[ \$(grep -n 'check-config' '$d/log' | cut -d: -f1) -lt \$(grep -n '^compose up' '$d/log' | cut -d: -f1) ]"
check "credentials file written, mode 0600" bash -c "[ \$(stat -c %a '$d/first-admin.txt') = 600 ] && grep -q TEMPSECRET '$d/first-admin.txt'"
check "bootstrap-admin got both administrators" grep -q "bootstrap-admin -email=admin@example.com -backup-email=breakglass@example.com -print-secrets" "$d/log"
check "summary names the app URL" grep -q "App:       https://ctem.example.com" "$d/out"
check "summary reports the sensor enrolled" grep -q "Bundled sensor: enrolled" "$d/out"
leak=""
for name in DB_SUPERUSER_PASSWORD DB_MIGRATE_PASSWORD DB_ADMIN_PASSWORD DB_PASSWORD REDIS_PASSWORD \
	APP_ENCRYPTION_KEY FINGERPRINT_KEY METRICS_TOKEN SENSOR_INSTANCE_ENROLLMENT_TOKEN; do
	v="$(sed -n "s/^$name=//p" "$d/deploy/.env")"
	[ -n "$v" ] || leak="$leak $name(empty)"
	grep -qF -- "$v" "$d/out" && leak="$leak $name"
done
grep -q TEMPSECRET "$d/out" && leak="$leak one-time-credential"
check "no secret on stdout or stderr${leak:+ (leaked:$leak)}" [ -z "$leak" ]

# 5. A second run reuses .env untouched and does not bootstrap again.
sum="$(sha256sum "$d/deploy/.env")"
rm -f "$d/log"
rc="$(run_install "$d" "${full_args[@]}" --credentials-file "$d/second.txt")"
check "rerun: exit 0" [ "$rc" = 0 ] || cat "$d/out"
check "rerun: .env not changed" [ "$(sha256sum "$d/deploy/.env")" = "$sum" ]
check "rerun: no second bootstrap" bash -c "! grep -q bootstrap-admin '$d/log' && [ ! -e '$d/second.txt' ]"
check "rerun: says it reuses .env" grep -q "reusing .*/.env" "$d/out"

# 6. Dropping the sensor changes COMPOSE_FILE, with a backup and the change printed.
rc="$(run_install "$d" --yes --no-sensor)"
check "--no-sensor: exit 0" [ "$rc" = 0 ] || cat "$d/out"
check "--no-sensor: COMPOSE_FILE without the sensor" grep -qx "COMPOSE_FILE=docker-compose.yml" "$d/deploy/.env"
check "--no-sensor: backup of .env, mode 0600" bash -c "ls '$d'/deploy/.env.bak-* >/dev/null && [ \$(stat -c %a '$d'/deploy/.env.bak-*) = 600 ]"
check "--no-sensor: change printed" grep -q "changed COMPOSE_FILE from docker-compose.yml:docker-compose.sensor.yml to docker-compose.yml" "$d/out"
check "--set on an existing .env with another value fails" [ "$(run_install "$d" --yes --set GATEWAY_HTTPS_PORT=4443)" != 0 ]
check "--host other than the .env's fails" [ "$(run_install "$d" --yes --host other.example.com)" != 0 ]
check "--version other than the .env's fails" [ "$(run_install "$d" --yes --version v9.9.10)" != 0 ]

# 7. An older .env without COMPOSE_FILE (written by setup.sh before) gets it added.
d="$(fixture)"
(cd "$d/deploy" && bash ./setup.sh ctem.example.com --version v9.9.9 >/dev/null)
sed -i '/^COMPOSE_FILE=/d' "$d/deploy/.env"
rc="$(run_install "$d" --yes --no-sensor)"
check "old .env: exit 0" [ "$rc" = 0 ] || cat "$d/out"
check "old .env: COMPOSE_FILE added and printed" bash -c "grep -qx 'COMPOSE_FILE=docker-compose.yml' '$d/deploy/.env' && grep -q 'added COMPOSE_FILE=docker-compose.yml' '$d/out'"
check "old .env: no administrator answer, no bootstrap, command printed" bash -c "! grep -q bootstrap-admin '$d/log' && grep -q 'docker compose run --rm bootstrap-admin' '$d/out'"

# 8. Typed values are validated; a refused secret is never echoed.
d="$(fixture)"
for kv in "REDIS_PASSWORD=tooshort" "DB_PASSWORD=p@ss:word/with-url-chars-0123456789" "DB_PASSWORD=has\$dollar0123456789abcdefgh" \
	"APP_ENCRYPTION_KEY=nothex" "OPENCTEM_TRUSTED_PROXIES=a #comment" "lower=1" "COMPOSE_FILE=other.yml"; do
	rc="$(run_install "$d" --yes --host ctem.example.com --version v9.9.9 --set "$kv")"
	check "--set ${kv%%=*} (bad value) refused" [ "$rc" != 0 ]
	case "${kv%%=*}" in *PASSWORD | *_KEY) check "--set ${kv%%=*}: value not echoed" bash -c "! grep -qF -- '${kv#*=}' '$d/out'" ;; esac
done
check "a refused --set writes no .env" [ ! -e "$d/deploy/.env" ]
check "lib: a good secret is accepted" bash -c "here='$d/deploy'; . '$d/deploy/lib/common.sh'; valid_setting REDIS_PASSWORD \$(printf 'x%.0s' \$(seq 1 40))"
check "lib: env_get reads data, never runs it" bash -c "f=\$(mktemp); printf 'A=\$(touch /tmp/should-not-exist-\$\$)\nB=\"quoted\"  # c\n' >\$f; here=/tmp; . '$d/deploy/lib/common.sh'; [ \"\$(env_get \$f B)\" = quoted ] && env_get \$f A >/dev/null && [ ! -e /tmp/should-not-exist-\$\$ ]; rm -f \$f"

# 9. setup.sh: --set lands in the new file; an existing .env is never overwritten.
d="$(fixture)"
(cd "$d/deploy" && bash ./setup.sh ctem.example.com --version v9.9.9 --set GATEWAY_HTTPS_PORT=4443 --set OPENCTEM_NET_PREFIX=172.30.99 >/dev/null)
check "setup --set replaces a line" grep -qx "GATEWAY_HTTPS_PORT=4443" "$d/deploy/.env"
check "setup --set appends a new line" grep -qx "OPENCTEM_NET_PREFIX=172.30.99" "$d/deploy/.env"
sum="$(sha256sum "$d/deploy/.env")"
check "setup refuses an existing .env" bash -c "! (cd '$d/deploy' && bash ./setup.sh ctem.example.com --version v9.9.9 >/dev/null 2>&1)"
check "setup left it untouched" [ "$(sha256sum "$d/deploy/.env")" = "$sum" ]

# 10. A signature that does not verify stops before anything is pulled or started.
d="$(fixture)"
rc="$(STUB_BAD_SIG=1 run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
check "bad signature: fails" [ "$rc" != 0 ]
check "bad signature: nothing pulled or started" bash -c "! grep -q '^compose \(pull\|up\)' '$d/log'"
check "bad signature: prints the command to see why" grep -q "cosign" "$d/out"

# 11. A tag that moved between the check and the pull stops before up.
d="$(fixture)"
rc="$(STUB_MOVED=1 run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
check "moved tag: fails before up" bash -c "[ '$rc' != 0 ] && ! grep -q '^compose up' '$d/log' && grep -q 'changed between the signature check and the pull' '$d/out'"

# 12. --no-verify says so loudly and prints the commands to verify by hand.
d="$(fixture)"
rc="$(run_install "$d" --yes --host ctem.example.com --version v9.9.9 --no-verify)"
check "--no-verify: exit 0" [ "$rc" = 0 ] || cat "$d/out"
check "--no-verify: warns and prints cosign verify commands" bash -c "grep -q 'SIGNATURE CHECK SKIPPED' '$d/out' && grep -q 'cosign verify ghcr.io/openctemio/openctem-api:v9.9.9' '$d/out' && ! grep -q '^run' '$d/log'"

# 13. A custom server image needs its own identity: refused by the release check.
d="$(fixture)"
(cd "$d/deploy" && bash ./setup.sh ctem.example.com --version v9.9.9 --set API_IMAGE=registry.example.com/team/server >/dev/null)
rc="$(run_install "$d" --yes --no-sensor)"
check "custom image: refused" bash -c "[ '$rc' != 0 ] && grep -q 'not a release image' '$d/out' && ! grep -q '^compose pull' '$d/log'"

# 14. Guards on a running stack.
d="$(fixture)"
rc="$(STUB_PS_DIR=/srv/elsewhere run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
check "stack of the same name elsewhere: fails with the line to add" bash -c "[ '$rc' != 0 ] && grep -q 'COMPOSE_PROJECT_NAME=' '$d/out' && ! grep -q '^compose up' '$d/log'"
d="$(fixture)"
rc="$(STUB_PS_DIR="$d/deploy" STUB_PS_FILES="$d/deploy/docker-compose.yml,$d/deploy/docker-compose.http-redirect.yml" run_install "$d" --yes --host ctem.example.com --version v9.9.9 --no-sensor)"
check "overlay the run would drop: fails with the COMPOSE_FILE line" bash -c "[ '$rc' != 0 ] && grep -q 'COMPOSE_FILE=docker-compose.yml:docker-compose.http-redirect.yml' '$d/out' && ! grep -q '^compose up' '$d/log'"

# 15. Host checks: a busy port stops the install (all problems listed); --force continues.
d="$(fixture)"
rc="$(STUB_BUSY_PORT=443 run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
check "busy port: fails before .env" bash -c "[ '$rc' != 0 ] && grep -q 'port 443 is in use' '$d/out' && [ ! -e '$d/deploy/.env' ]"
rc="$(STUB_BUSY_PORT=443 run_install "$d" --yes --host ctem.example.com --version v9.9.9 --force)"
check "busy port with --force: continues" [ "$rc" = 0 ]
d="$(fixture)"
rc="$(STUB_COMPOSE=2.17.0 run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
check "old Compose: fails" bash -c "[ '$rc' != 0 ] && grep -q 'older than 2.24.0' '$d/out'"

# 16. An IP address: no sensor by default.
d="$(fixture)"
rc="$(run_install "$d" --yes --host 192.0.2.10 --version v9.9.9)"
check "IP host: no sensor overlay by default" bash -c "[ '$rc' = 0 ] && grep -qx 'COMPOSE_FILE=docker-compose.yml' '$d/deploy/.env'"

# 17. A rerun with the same console options passes; a different one names the line.
d="$(fixture)"
rc="$(run_install "$d" --yes --host ctem.example.com --version v9.9.9 --no-sensor --admin-port 28444)"
check "console option: first run exit 0" [ "$rc" = 0 ]
rc="$(run_install "$d" --yes --no-sensor --admin-port 28444)"
check "console option equal to .env: exit 0, no warning" bash -c "[ '$rc' = 0 ] && ! grep -q 'ignored' '$d/out'"
rc="$(run_install "$d" --yes --no-sensor --admin-port 28445)"
check "console option different from .env: fails naming the line" bash -c "[ '$rc' != 0 ] && grep -q 'OPENCTEM_ADMIN_PORT=28444' '$d/out'"

# 18. The configuration check: skipped while the API runs (its throwaway
# container cannot take the API's fixed address), and its failures told apart.
rm -f "$d/log"
rc="$(STUB_API_RUNNING=1 run_install "$d" --yes --no-sensor)"
check "API running: no throwaway check-config container, exit 0" bash -c "[ '$rc' = 0 ] && ! grep -q check-config '$d/log' && grep -q 'the API is running' '$d/out'"
d="$(fixture)"
rc="$(STUB_CHECK=invalid run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
check "invalid configuration: fails before up, says so" bash -c "[ '$rc' != 0 ] && grep -q 'refuses this configuration' '$d/out' && ! grep -q '^compose up' '$d/log'"
d="$(fixture)"
rc="$(STUB_CHECK=docker run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
check "check that could not run: not blamed on the configuration" bash -c "[ '$rc' != 0 ] && grep -q 'could not run' '$d/out' && ! grep -q 'refuses this configuration' '$d/out'"

# 19. A git checkout not at a release tag never installs its stale VERSION.
d="$(fixture)"
printf 'v0.20.1\n' >"$d/deploy/VERSION"
g() { GIT_CONFIG_GLOBAL=/dev/null git -C "$d" -c user.name=t -c user.email=t@example.com "$@" >/dev/null 2>&1; }
g init -q && g add deploy && g commit -q -m init
rc="$(run_install "$d" --yes --host ctem.example.com --no-sensor)"
check "checkout off a tag, no --version: fails, writes nothing" bash -c "[ '$rc' != 0 ] && grep -q 'not at a release tag' '$d/out' && grep -q -- '--version' '$d/out' && [ ! -e '$d/deploy/.env' ]"
rc="$(run_install "$d" --yes --host ctem.example.com --no-sensor --version v9.9.9)"
check "checkout off a tag, --version given: installs it" bash -c "[ '$rc' = 0 ] && grep -qx 'OPENCTEM_VERSION=v9.9.9' '$d/deploy/.env'"
mv "$d/deploy/.env" "$d/env.first"
g tag v9.9.8
rc="$(run_install "$d" --yes --host ctem.example.com --no-sensor)"
check "checkout at a release tag: installs the tag, not VERSION" bash -c "[ '$rc' = 0 ] && grep -qx 'OPENCTEM_VERSION=v9.9.8' '$d/deploy/.env'"
d="$(fixture)"
printf 'v9.9.7\n' >"$d/deploy/VERSION"
rc="$(run_install "$d" --yes --host ctem.example.com --no-sensor)"
check "bundle (no git): installs its VERSION" bash -c "[ '$rc' = 0 ] && grep -qx 'OPENCTEM_VERSION=v9.9.7' '$d/deploy/.env'"

# 20. A rerun without --sensor/--no-sensor keeps what the install has.
d="$(fixture)"
rc="$(run_install "$d" --yes --host ctem.example.com --version v9.9.9 --no-sensor)"
rc="$(run_install "$d" --yes)"
check "rerun without a sensor flag keeps a no-sensor install (DNS name)" bash -c "[ '$rc' = 0 ] && grep -qx 'COMPOSE_FILE=docker-compose.yml' '$d/deploy/.env'"

# 21. The running-stack guard refuses before .env is touched.
d="$(fixture)"
rc="$(run_install "$d" --yes --host ctem.example.com --version v9.9.9)"
sum="$(sha256sum "$d/deploy/.env")"
running="$d/deploy/docker-compose.yml,$d/deploy/docker-compose.sensor.yml,$d/deploy/docker-compose.http-redirect.yml"
rc="$(STUB_PS_DIR="$d/deploy" STUB_PS_FILES="$running" run_install "$d" --yes --no-sensor)"
check "guard refusal: fails naming the overlay" bash -c "[ '$rc' != 0 ] && grep -q 'COMPOSE_FILE=docker-compose.yml:docker-compose.http-redirect.yml' '$d/out'"
check "guard refusal: .env untouched, no backup" bash -c "[ \"\$(sha256sum '$d/deploy/.env')\" = '$sum' ] && ! ls '$d'/deploy/.env.bak-* >/dev/null 2>&1"

# 22. Dropping the running sensor: only on an explicit --no-sensor.
running="$d/deploy/docker-compose.yml,$d/deploy/docker-compose.sensor.yml"
sed -i 's/^COMPOSE_FILE=.*/COMPOSE_FILE=docker-compose.yml/' "$d/deploy/.env"
rc="$(STUB_PS_DIR="$d/deploy" STUB_PS_FILES="$running" run_install "$d" --yes)"
check "sensor running, .env edited without it, no flag: kept (rerun keeps the running set)" bash -c "[ '$rc' != 0 ] && grep -q 'COMPOSE_FILE=docker-compose.yml:docker-compose.sensor.yml' '$d/out'"
rc="$(STUB_PS_DIR="$d/deploy" STUB_PS_FILES="$running" run_install "$d" --yes --no-sensor)"
check "sensor running, explicit --no-sensor: allowed" bash -c "[ '$rc' = 0 ] && grep -qx 'COMPOSE_FILE=docker-compose.yml' '$d/deploy/.env'"

echo "${pass} passed, ${failed} failed"
[ "$failed" -eq 0 ]
