#!/usr/bin/env bash
# Tests for support.sh with a stub docker (no containers).
# Run: bash server/deploy/support.test.sh
set -euo pipefail
src="$(cd "$(dirname "$0")" && pwd)/support.sh"
pass=0 failed=0
ok() {
	echo "ok:   $1"
	pass=$((pass + 1))
}
bad() {
	echo "FAIL: $1"
	failed=$((failed + 1))
}

# fixture: a copy of support.sh next to a stub bin dir; prints the work dir.
# The stub records every call in $d/calls. `compose exec|run ... support-bundle`
# copies its standard input to $d/stdin and prints a fake archive.
fixture() {
	local d
	d="$(mktemp -d)"
	mkdir -p "$d/bin" "$d/deploy" "$d/out"
	cp "$src" "$d/deploy/support.sh"
	cat >"$d/bin/docker" <<'STUB'
#!/usr/bin/env bash
root="$(cd "$(dirname "$0")/.." && pwd)"
echo "$*" >>"$root/calls"
[ "$1" = compose ] || exit 0
shift
case "$1" in
ps) [ -n "${API_DOWN:-}" ] || echo api ;;
config) printf '%s\n' ${SERVICES:-api web gateway postgres redis migrate} ;;
logs) echo "api-1  | {\"msg\":\"a log line\"}" ;;
exec | run)
	case "$*" in
	*support-bundle*)
		cat >"$root/stdin"
		[ -n "${NO_ARCHIVE:-}" ] || printf 'ARCHIVE'
		;;
	*doctor*)
		echo "STATUS  CHECK  RESULT"
		exit "${DOCTOR_RC:-0}"
		;;
	esac
	;;
esac
STUB
	chmod +x "$d/bin/docker"
	echo "$d"
}
run() { # run <dir> <args...>: support.sh with the stub docker first in PATH, in $d/out
	local d="$1"
	shift
	(cd "$d/out" && PATH="$d/bin:$PATH" bash "$d/deploy/support.sh" "$@")
}

# 1. doctor runs in the running api container and passes its exit code on.
d="$(fixture)"
out="$(run "$d" doctor --json)"
if grep -q "compose exec -T api /app/server doctor --json" "$d/calls" && [[ "$out" == STATUS* ]]; then ok "doctor runs in the api container"; else bad "doctor call: $(cat "$d/calls")"; fi
rc=0
DOCTOR_RC=1 run "$d" doctor >/dev/null || rc=$?
if [[ $rc -eq 1 ]]; then ok "doctor's exit code is passed on"; else bad "doctor exit code $rc, want 1"; fi
rm -rf "$d"

# 2. With the api container down, a one-off container of the same service runs the command.
d="$(fixture)"
API_DOWN=1 run "$d" doctor >/dev/null 2>&1
if grep -q "compose run --rm --no-deps -T api doctor" "$d/calls"; then ok "doctor falls back to a one-off container"; else bad "fallback: $(cat "$d/calls")"; fi
rm -rf "$d"

# 3. bundle pipes the logs of the application services (never the database's) into the command.
d="$(fixture)"
run "$d" bundle --since 2h --max-size 5M --output b.tar.gz 2>/dev/null
if grep -q "compose logs --no-color --since 2h api web gateway migrate$" "$d/calls"; then ok "logs of the application services only"; else bad "logs call: $(grep logs "$d/calls")"; fi
if grep -q "exec -T api /app/server support-bundle --logs - --output - --since 2h --max-size 5M" "$d/calls"; then ok "bundle options are passed on"; else bad "bundle call: $(grep support-bundle "$d/calls")"; fi
if grep -q "a log line" "$d/stdin"; then ok "the logs reach the command's standard input"; else bad "stdin: $(cat "$d/stdin")"; fi
if [[ "$(cat "$d/out/b.tar.gz")" == ARCHIVE && "$(stat -c %a "$d/out/b.tar.gz")" == 600 ]]; then ok "the archive is written with mode 0600"; else bad "archive missing or not 0600"; fi

# 4. An existing file is never replaced.
if run "$d" bundle --output b.tar.gz >/dev/null 2>&1; then bad "an existing archive was replaced"; else ok "an existing archive is not replaced"; fi
rm -rf "$d"

# 5. --no-logs reads no logs; a deployment with none of the services reads none either.
d="$(fixture)"
run "$d" bundle --no-logs --output b.tar.gz 2>/dev/null
if ! grep -q "compose logs" "$d/calls" && grep -q "support-bundle --output - " "$d/calls"; then ok "--no-logs reads no logs"; else bad "--no-logs: $(cat "$d/calls")"; fi
rm -rf "$d"
d="$(fixture)"
SERVICES="postgres redis" run "$d" bundle --output b.tar.gz 2>/dev/null
if ! grep -q "compose logs" "$d/calls"; then ok "no application service, no logs read"; else bad "logs read without a service name"; fi
rm -rf "$d"

# 6. No archive from the command: no file is left behind, and the script fails.
d="$(fixture)"
if NO_ARCHIVE=1 run "$d" bundle --output b.tar.gz >/dev/null 2>&1; then bad "an empty archive was accepted"; else ok "an empty archive fails"; fi
if [[ -z "$(ls "$d/out")" ]]; then ok "nothing is left behind"; else bad "left behind: $(ls "$d/out")"; fi
rm -rf "$d"

# 7. Bad input is refused before anything runs.
d="$(fixture)"
for args in "bundle --since yesterday" "bundle --bogus" "frobnicate"; do
	# shellcheck disable=SC2086 # the words of $args are separate arguments
	if run "$d" $args >/dev/null 2>&1; then bad "accepted: $args"; else ok "refused: $args"; fi
done
if [[ ! -s "$d/calls" ]] || ! grep -q "support-bundle\|frobnicate" "$d/calls"; then ok "nothing ran for bad input"; else bad "ran: $(cat "$d/calls")"; fi
rm -rf "$d"

echo "$pass passed, $failed failed"
[[ $failed -eq 0 ]]
