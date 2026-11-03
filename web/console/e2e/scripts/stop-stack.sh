#!/usr/bin/env bash
# Stops what start-stack.sh started: only the PIDs it recorded and their descendants.
set -uo pipefail
pids="${STACK_DIR:?set STACK_DIR}/pids"
[[ -f "$pids" ]] || exit 0

descendants() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null); do
    descendants "$child"
    echo "$child"
  done
}

while read -r pid; do
  [[ -n "$pid" ]] || continue
  for d in $(descendants "$pid"); do kill "$d" 2>/dev/null || true; done
  kill "$pid" 2>/dev/null || true
done <"$pids"
: >"$pids"
