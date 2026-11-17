#!/usr/bin/env bash
# support.sh — check this Compose deployment and write a support bundle.
#
#   ./support.sh doctor [--json] [--offline]
#       Check the installation: a table of checks (pass, warn, fail), each
#       with one sentence and the fix. Exit code 0 only when nothing fails.
#
#   ./support.sh bundle [--since 24h] [--max-size 20M] [--output FILE] [--no-logs] [--offline]
#       Write one archive with the doctor's result, versions, the settings as
#       set / not set, database and queue statistics, and the logs of the
#       period with addresses, names, tokens and bodies masked. It holds no
#       database row, no finding, no asset or user name and no key: read it,
#       then send it.
#
# Both are thin wrappers around the server's own commands (`server doctor`,
# `server support-bundle`), run in the api container. They read; they change
# nothing. When the api container is not running (it keeps restarting), the
# command runs in a one-off container of the same image with the same
# settings.
#
# Guide: docs/operations/diagnose-and-get-support.md
set -euo pipefail
umask 077

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dc() { (cd "$here" && docker compose "$@"); }
die() {
	printf 'support: %s\n' "$*" >&2
	exit 1
}
usage() {
	sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

# The services whose logs go into a bundle. The database's log is left out on
# purpose: it can print statements with their values.
log_services=(api web console gateway migrate)

# server_cmd <args...>: run the server binary with these arguments, in the
# running api container, or in a one-off one when api is not running.
server_cmd() {
	if dc ps --status running --services 2>/dev/null | grep -qx api; then
		dc exec -T api /app/server "$@"
	else
		printf 'support: the api container is not running; using a one-off container of the same image\n' >&2
		dc run --rm --no-deps -T api "$@"
	fi
}

cmd="${1:-}"
[[ $# -gt 0 ]] && shift
case "$cmd" in
doctor)
	server_cmd doctor "$@"
	;;
bundle)
	since="24h"
	output=""
	logs="yes"
	pass=()
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--since)
			[[ $# -ge 2 ]] || die "--since needs a value (for example 24h)"
			since="$2"
			shift 2
			;;
		--since=*)
			since="${1#--since=}"
			shift
			;;
		--output)
			[[ $# -ge 2 ]] || die "--output needs a file name"
			output="$2"
			shift 2
			;;
		--output=*)
			output="${1#--output=}"
			shift
			;;
		--max-size)
			[[ $# -ge 2 ]] || die "--max-size needs a value (for example 20M)"
			pass+=(--max-size "$2")
			shift 2
			;;
		--max-size=*)
			pass+=("$1")
			shift
			;;
		--no-logs)
			logs=""
			shift
			;;
		--offline)
			pass+=(--offline)
			shift
			;;
		-h | --help) usage 0 ;;
		*) die "unknown option $1 (see ./support.sh --help)" ;;
		esac
	done
	[[ "$since" =~ ^[0-9]+(s|m|h)([0-9]+(s|m))*$ ]] || die "--since takes a duration such as 30m, 24h or 72h"
	output="${output:-openctem-support-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}"
	[[ -e "$output" ]] && die "$output exists already; choose another --output"
	tmp="$(mktemp "$output.XXXXXX")"
	trap 'rm -f "$tmp"' EXIT

	# Only the services this deployment has. With none of them there is
	# nothing to read: `docker compose logs` without a service name would
	# print every service, the database included.
	wanted=()
	have="$(dc config --services 2>/dev/null || true)"
	for s in "${log_services[@]}"; do
		if grep -qx "$s" <<<"$have"; then wanted+=("$s"); fi
	done
	if [[ -n "$logs" && ${#wanted[@]} -gt 0 ]]; then
		dc logs --no-color --since "$since" "${wanted[@]}" 2>/dev/null |
			server_cmd support-bundle --logs - --output - --since "$since" ${pass[@]+"${pass[@]}"} >"$tmp"
	else
		server_cmd support-bundle --output - --since "$since" ${pass[@]+"${pass[@]}"} >"$tmp" </dev/null
	fi
	[[ -s "$tmp" ]] || die "no archive was written (see the message above)"
	mv "$tmp" "$output"
	trap - EXIT
	printf 'support: wrote %s (mode 0600). Read it before you send it:\n  tar -xzf %s && less openctem-support/README.txt\n' "$output" "$output" >&2
	;;
-h | --help | help | "")
	usage 0
	;;
*)
	die "unknown command $cmd (see ./support.sh --help)"
	;;
esac
