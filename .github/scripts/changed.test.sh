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
expect "a top-level docs directory is docs" false false true docs/guide/x.png docs/index.html
expect "agent notes are docs" false false true .claude/skills/x/SKILL.md web/.claude/notes.md
expect "non-markdown under api/docs is docs" false false true api/docs/rfcs/sim/run.py
expect "generated env reference is api code" true false false api/docs/configuration/environment-variables.md
expect "docs plus code runs the code side" true false true api/docs/x.md api/internal/y.go

# expect_kv <name> <event> <labels> "<k=v ...>" <file>...: every k=v is in the
# output. pull_request diffs against origin/main (a remote that is this repo).
git -C "$d" remote add origin "$d"
expect_kv() {
  local name="$1" event="$2" labels="$3" want="$4" f out head kv ok=1; shift 4
  git -C "$d" checkout -q "$base"
  for f in "$@"; do mkdir -p "$d/$(dirname "$f")"; echo "$RANDOM" >> "$d/$f"; done
  git -C "$d" add -A; git -C "$d" commit -qm change
  head="$(git -C "$d" rev-parse HEAD)"
  out="$(cd "$d" && GITHUB_OUTPUT=/dev/null GITHUB_EVENT_NAME="$event" GITHUB_BASE_REF=main \
    MG_BASE="$base" MG_HEAD="$head" PR_LABELS="${labels:-[]}" PR_NUMBER="" GH_TOKEN="" bash "$script")"
  for kv in $want; do [[ "$out" == *"$kv"* ]] || ok=0; done
  if (( ok )); then
    echo "ok:   $name"; pass=$((pass + 1))
  else
    echo "FAIL: $name (want $want)"; echo "$out"; failed=$((failed + 1))
  fi
}

expect_kv "merge queue is always the full tier" merge_group "" "full=true migrations=false" web/src/a.tsx
expect_kv "migration change is flagged" merge_group "" "migrations=true api=true" api/migrations/000001_x.up.sql
expect_kv "role script change is flagged" pull_request "" "migrations=true full=false" api/deploy/postgres/least-privilege-roles.sql
expect_kv "plain PR is the fast tier" pull_request "" "full=false api=true" api/internal/x.go
expect_kv "ci:full label runs the full tier" pull_request '["run-e2e","ci:full"]' "full=true" api/internal/x.go
expect_kv "a similar label does not" pull_request '["ci:fuller"]' "full=false" api/internal/x.go
expect_kv "workflow change runs the full tier" pull_request "" "full=true api=true web=true" .github/workflows/x.yml
expect_kv "CI script change runs the full tier" pull_request "" "full=true" .github/scripts/x.sh
expect_kv "other .github files do not" pull_request "" "full=false api=true" .github/dependabot.yml
expect_kv "docs-only PR is the fast tier" pull_request "" "full=false api=false web=false" .github/workflows/README.md

echo "$pass passed, $failed failed"
(( failed == 0 ))
