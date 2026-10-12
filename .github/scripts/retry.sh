#!/usr/bin/env bash
# Run a registry-touching command (docker pull/run/build, docker compose pull,
# crane) and retry it with backoff when it failed on a registry rate limit or
# a transient network error. Any other failure is returned at once, so a real
# build error is not repeated.
#
#   bash .github/scripts/retry.sh docker build -t img .
#
# RETRY_ATTEMPTS (default 4) and RETRY_DELAY (first wait in seconds, default
# 15, doubled after each failure) tune it.
set -uo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: retry.sh <command> [args...]" >&2
  exit 2
fi

attempts="${RETRY_ATTEMPTS:-4}"
delay="${RETRY_DELAY:-15}"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# Registry quota and transient transport errors seen on shared runners.
transient='toomanyrequests|rate exceeded|data limit exceeded|too many requests|429 Too Many|503 Service Unavailable|502 Bad Gateway|504 Gateway|i/o timeout|TLS handshake timeout|connection reset by peer|unexpected EOF|net/http: request canceled'

for ((i = 1; ; i++)); do
  "$@" 2>&1 | tee "$log"
  rc="${PIPESTATUS[0]}"
  [ "$rc" -eq 0 ] && exit 0
  if [ "$i" -ge "$attempts" ] || ! grep -qiE "$transient" "$log"; then
    exit "$rc"
  fi
  echo "::warning::attempt $i/$attempts hit a registry limit or network error (exit $rc); retrying in ${delay}s"
  sleep "$delay"
  delay=$((delay * 2))
done
