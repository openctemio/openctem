#!/usr/bin/env bash
# Checks for the development tooling guards. Run from anywhere: bash api/scripts/dev-tools.test.sh
set -uo pipefail
api="$(cd "$(dirname "$0")/.." && pwd)"
pass=0 failed=0
ok() { echo "ok:   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; failed=$((failed + 1)); }

# migrate.sh: down-all needs --yes; .env values with spaces/specials are not word-split.
d="$(mktemp -d)"
mkdir -p "$d/bin"
printf '#!/bin/sh\necho "migrate $*" >>"%s/calls"\n' "$d" >"$d/bin/migrate"
chmod +x "$d/bin/migrate"
printf "DB_PASSWORD=pw\nDB_USER=u\nSPACED='hello world \$(touch %s/pwned)'\n" "$d" >"$d/.env"
run() { (cd "$d" && PATH="$d/bin:$PATH" bash "$api/scripts/migrate.sh" "$@" >"$d/out" 2>&1); }
if run down-all; then bad "down-all without --yes ran"; else ok "down-all without --yes is refused"; fi
[ ! -e "$d/calls" ] && ok "down-all without --yes did not call migrate" || bad "migrate was called"
run down-all --yes && grep -q 'down -all' "$d/calls" && ok "down-all --yes runs" || bad "down-all --yes failed: $(tail -2 "$d/out")"
[ ! -e "$d/pwned" ] && ok "quoted .env values with spaces and $() are kept literal" || bad "a quoted .env value was executed or split"

# the secret-bearing legacy tool and script are gone / env only.
[ ! -e "$api/scripts/dev-setup-admin.sh" ] && ok "dev-setup-admin.sh removed" || bad "dev-setup-admin.sh still present"
! grep -qE 'flag\.String\("(key|db)"' "$api/cmd/encrypt-credentials/main.go" "$api/cmd/seed/main.go" && ok "encrypt-credentials and seed have no -db/-key flag" || bad "encrypt-credentials or seed still takes a secret flag"

# dev compose: loopback only, no default password.
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
	cfg="$(cd "$api" && DB_PASSWORD=x docker compose -f docker-compose.yml -f docker-compose.dev.yml config 2>&1)"
	! grep -E 'host_ip: 0\.0\.0\.0' <<<"$cfg" >/dev/null && ok "dev compose publishes no port on 0.0.0.0" || bad "dev compose publishes on 0.0.0.0"
	if (cd "$api" && env -u DB_PASSWORD docker compose -f docker-compose.yml -f docker-compose.dev.yml config >/dev/null 2>&1); then bad "dev compose works without DB_PASSWORD"; else ok "dev compose requires DB_PASSWORD"; fi
else
	! grep -E '^\s*- "(\$\{[A-Z_]+:-[0-9]+\}|[0-9]+):[0-9]+"' "$api/docker-compose.yml" "$api/docker-compose.dev.yml" >/dev/null && ok "dev compose ports are all bound to 127.0.0.1" || bad "dev compose has an unbound port"
	! grep -q ':-secret}' "$api/docker-compose.yml" "$api/docker-compose.dev.yml" && ok "dev compose has no default password" || bad "default password present"
fi
echo "passed: $pass failed: $failed"
[ "$failed" = 0 ]
