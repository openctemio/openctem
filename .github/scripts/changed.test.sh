#!/usr/bin/env bash
# Tests for changed.sh. Run: bash .github/scripts/changed.test.sh
# Builds a throwaway git repository and replays merge_group events; touches nothing here.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/changed.sh"
pass=0 failed=0

d="$(mktemp -d)"
git -C "$d" init -q -b main
git -C "$d" config user.name t; git -C "$d" config user.email t@example.invalid
mkdir -p "$d/api/docs/configuration" "$d/web/src" "$d/.github"
echo x > "$d/README.md"; git -C "$d" add -A; git -C "$d" commit -qm base
base="$(git -C "$d" rev-parse HEAD)"

# expect <name> <api> <web> <docs> <file>...: a change of exactly these files.
expect() {
  local name="$1" api="$2" web="$3" docs="$4" f out head; shift 4
  git -C "$d" checkout -q "$base"
  for f in "$@"; do mkdir -p "$d/$(dirname "$f")"; echo "$RANDOM" >> "$d/$f"; done
  git -C "$d" add -A; git -C "$d" commit -qm change
  head="$(git -C "$d" rev-parse HEAD)"
  out="$(cd "$d" && GITHUB_OUTPUT=/dev/null GITHUB_EVENT_NAME=merge_group MG_BASE="$base" MG_HEAD="$head" bash "$script")"
  if [[ "$out" == *"api=$api"* && "$out" == *"web=$web"* && "$out" == *"docs=$docs"* ]]; then
    echo "ok:   $name"; pass=$((pass + 1))
  else
    echo "FAIL: $name (want api=$api web=$web docs=$docs)"; echo "$out"; failed=$((failed + 1))
  fi
}

expect "go change runs api only" true false false api/internal/x.go
expect "web change runs web only" false true false web/src/a.tsx
expect "shared file runs both" true true false .github/workflows/x.yml
expect "RFC and changelog fragment run neither" false false true api/docs/rfcs/RFC-999.md api/changelog.d/x.md
expect "markdown anywhere is docs" false false true README.md web/README.md .github/PULL_REQUEST_TEMPLATE.md
expect "agent notes are docs" false false true .claude/skills/x/SKILL.md web/.claude/notes.md
expect "non-markdown under api/docs is docs" false false true api/docs/rfcs/sim/run.py
expect "generated env reference is api code" true false false api/docs/configuration/environment-variables.md
expect "docs plus code runs the code side" true false true api/docs/x.md api/internal/y.go

echo "$pass passed, $failed failed"
(( failed == 0 ))
