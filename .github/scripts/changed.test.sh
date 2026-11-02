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
expect_kv "migration change runs the schema tests" pull_request "" "schema=true" api/migrations/000001_x.up.sql
expect_kv "postgres repository change runs the schema tests" pull_request "" "schema=true migrations=false" api/internal/infra/postgres/a.go
expect_kv "unrelated api change skips the schema tests" pull_request "" "schema=false" api/internal/app/a.go
expect_kv "role script change is flagged" pull_request "" "migrations=true full=false" api/deploy/postgres/least-privilege-roles.sql
expect_kv "plain PR is the fast tier" pull_request "" "full=false api=true" api/internal/x.go
expect_kv "ci:full label runs the full tier" pull_request '["run-e2e","ci:full"]' "full=true" api/internal/x.go
expect_kv "a similar label does not" pull_request '["ci:fuller"]' "full=false" api/internal/x.go
expect_kv "workflow change runs the full tier" pull_request "" "full=true api=true web=true" .github/workflows/x.yml
expect_kv "CI script change runs the full tier" pull_request "" "full=true" .github/scripts/x.sh
expect_kv "other .github files do not" pull_request "" "full=false api=true" .github/dependabot.yml
expect_kv "docs-only PR is the fast tier" pull_request "" "full=false api=false web=false" .github/workflows/README.md

# Incremental pull request CI: a fake `gh` answers the PR's commits and their
# check runs; the PR is base -> A (api) -> B (web) -> head.
fake="$(mktemp -d)"; mkdir -p "$fake/bin" "$fake/data"
cat >"$fake/bin/gh" <<'GH'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    *pulls/*/commits*) cat "$FAKE/commits"; exit 0 ;;
    *commits/*/check-runs*) sha="${a#*commits/}"; sha="${sha%%/*}"
      [[ -f "$FAKE/$sha.json" ]] || exit 1
      jq -c '.[]' "$FAKE/$sha.json"; exit 0 ;;
  esac
done
exit 1
GH
chmod +x "$fake/bin/gh"
green() { local n; for n in "API CI OK" "Web CI OK" "CodeQL OK" "E2E OK" "All-in-one OK" "Secret Scanning" "Workflow Lint"; do
  printf '{"name":"%s","status":"completed","conclusion":"%s","app":"github-actions"}\n' "$n" "${1:-success}"; done | jq -s -c '.'; }
mkpr() { # mkpr <file>...: base -> A (first file) -> B (the rest) -> head
  git -C "$d" checkout -q "$base"
  mkdir -p "$d/$(dirname "$1")"; echo "$RANDOM" >> "$d/$1"; git -C "$d" add -A; git -C "$d" commit -qm A
  A="$(git -C "$d" rev-parse HEAD)"; shift
  local f; for f in "$@"; do mkdir -p "$d/$(dirname "$f")"; echo "$RANDOM" >> "$d/$f"; done
  git -C "$d" add -A; git -C "$d" commit -qm B
  H="$(git -C "$d" rev-parse HEAD)"
  printf '%s\n%s\n' "$A" "$H" >"$fake/data/commits"
}
inc() { # inc <name> <action> "<k=v ...>"
  local name="$1" action="$2" want="$3" out kv ok=1
  out="$(cd "$d" && FAKE="$fake/data" PATH="$fake/bin:$PATH" GITHUB_OUTPUT=/dev/null GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF=main \
    GITHUB_REPOSITORY=o/r EVENT_ACTION="$action" PR_HEAD_SHA="$H" PR_NUMBER=7 GH_TOKEN=x PR_LABELS='[]' bash "$script" 2>&1)"
  for kv in $want; do [[ "$out" == *"$kv"* ]] || ok=0; done
  if (( ok )); then echo "ok:   $name"; pass=$((pass + 1)); else echo "FAIL: $name (want $want)"; echo "$out"; failed=$((failed + 1)); fi
}
rm -f "$fake"/data/*.json
mkpr api/internal/a.go web/src/b.tsx
green > "$fake/data/$A.json"
inc "after a green commit only the later change runs" synchronize "api=false web=true incremental=true unchanged since"
inc "a PR opened is measured against the base" opened "api=true web=true incremental=false"
rm "$fake/data/$A.json"
inc "no green commit measures against the base" synchronize "api=true web=true incremental=false"
green failure > "$fake/data/$A.json"
inc "a red commit is not a base" synchronize "api=true web=true incremental=false"
mkpr api/internal/a.go .github/workflows/x.yml
green > "$fake/data/$A.json"
inc "a PR that changes .github is never incremental" synchronize "api=true web=true full=true incremental=false"
# A CI edit in the green commit, reverted later: that commit's checks ran a CI
# the PR no longer has, so they vouch for nothing.
git -C "$d" checkout -q "$base"
mkdir -p "$d/.github/workflows" "$d/api/internal"
echo fake > "$d/.github/workflows/fake.yml"; echo "$RANDOM" >> "$d/api/internal/evil.go"
git -C "$d" add -A; git -C "$d" commit -qm A; A="$(git -C "$d" rev-parse HEAD)"
git -C "$d" rm -q .github/workflows/fake.yml; git -C "$d" commit -qm revert
H="$(git -C "$d" rev-parse HEAD)"; printf '%s\n%s\n' "$A" "$H" >"$fake/data/commits"
green > "$fake/data/$A.json"
inc "a green commit with a CI edit reverted since is not a base" synchronize "api=true incremental=false"
mkpr api/internal/a.go README.md
green > "$fake/data/$A.json"
inc "only docs since the green commit runs no suite" synchronize "api=false web=false docs=true incremental=true"
mkpr api/internal/a.go api/migrations/000001_x.up.sql
green > "$fake/data/$A.json"
inc "a migration since the green commit is flagged" synchronize "migrations=true api=true incremental=true"

echo "$pass passed, $failed failed"
(( failed == 0 ))
