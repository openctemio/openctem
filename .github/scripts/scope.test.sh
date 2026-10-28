#!/usr/bin/env bash
# Tests for scope.sh. Run: bash .github/scripts/scope.test.sh
# Builds a throwaway git repository and replays merge_group and pull_request
# events; touches nothing here.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/scope.sh"
pass=0 failed=0

d="$(mktemp -d)"
trap 'find "$d" -delete 2>/dev/null || true' EXIT
git -C "$d" init -q -b main
git -C "$d" config user.name t; git -C "$d" config user.email t@example.invalid
mkdir -p "$d/.github/workflows" "$d/.github/scripts" "$d/.github/actions/go-cache"
cat > "$d/.github/workflows/web-ci.yml" <<'EOF'
jobs: { a: { steps: [ { run: bash .github/scripts/changed.sh }, { uses: ./.github/actions/go-cache } ] } }
EOF
echo 'jobs: { a: { steps: [ { run: bash .github/scripts/go-shard-run.sh } ] } }' > "$d/.github/workflows/api-ci.yml"
echo 'bash "$here/go-shard.sh" plan; python3 quarantine.py' > "$d/.github/scripts/go-shard-run.sh"
echo 'echo shard' > "$d/.github/scripts/go-shard.sh"
echo 'open(".github/quarantine.yml")' > "$d/.github/scripts/quarantine.py"
echo '[]' > "$d/.github/quarantine.yml"
echo 'echo changed' > "$d/.github/scripts/changed.sh"
echo 'runs: { using: composite }' > "$d/.github/actions/go-cache/action.yml"
echo 'version: 2' > "$d/.github/dependabot.yml"
echo x > "$d/README.md"
git -C "$d" add -A; git -C "$d" commit -qm base
base="$(git -C "$d" rev-parse HEAD)"
git -C "$d" remote add origin "$d"
git -C "$d" fetch -q origin

# expect <name> <event> <workflow> "<k=v ...>" <file>...: a change of exactly
# these files; every k=v must be in the output.
expect() {
  local name="$1" event="$2" wf="$3" want="$4" f out head kv ok=1; shift 4
  git -C "$d" checkout -q "$base"
  for f in "$@"; do mkdir -p "$d/$(dirname "$f")"; echo "$RANDOM" >> "$d/$f"; done
  git -C "$d" add -A; git -C "$d" commit -qm change
  head="$(git -C "$d" rev-parse HEAD)"
  out="$(cd "$d" && GITHUB_OUTPUT=/dev/null GITHUB_EVENT_NAME="$event" GITHUB_BASE_REF=main \
    MG_BASE="$base" MG_HEAD="$head" WORKFLOW_FILE="$wf" GITHUB_WORKFLOW_REF="" bash "$script")"
  for kv in $want; do grep -qE "^${kv}( |$)" <<<"$out" || ok=0; done
  if (( ok )); then
    echo "ok:   $name"; pass=$((pass + 1))
  else
    echo "FAIL: $name (want $want)"; echo "$out"; failed=$((failed + 1))
  fi
}

W=.github/workflows/web-ci.yml A=.github/workflows/api-ci.yml
expect "e2e spec only is test-only" merge_group "$W" "web_e2e=true web_app=false api_code=false web_i18n=false ci_self=false" \
  web/e2e/specs/41-attack-path-canvas.spec.ts
expect "e2e spec on a pull request" pull_request "$W" "web_e2e=true web_app=false" web/e2e/fixtures/auth.ts
expect "web source is app code" merge_group "$W" "web_app=true web_e2e=false" web/src/app/page.tsx
expect "web unit test is app code" merge_group "$W" "web_app=true" web/src/lib/x.test.ts
expect "web config is app code" merge_group "$W" "web_app=true" web/package-lock.json
expect "vi catalog is i18n only" merge_group "$W" "web_i18n=true i18n_en=false web_app=false" \
  web/src/lib/i18n/dictionaries/vi/findings.json
expect "catalog paths are listed relative to web/" merge_group "$W" "i18n_files=src/lib/i18n/dictionaries/vi/a.json" \
  web/src/lib/i18n/dictionaries/vi/a.json
expect "en catalog flags i18n_en" merge_group "$W" "web_i18n=true i18n_en=true web_app=false" \
  web/src/lib/i18n/dictionaries/en/findings.json
expect "i18n test file is app code" merge_group "$W" "web_app=true web_i18n=false" \
  web/src/lib/i18n/dictionaries/dictionaries.test.ts
expect "go is api code" merge_group "$A" "api_code=true web_app=false" api/internal/x.go
expect "shared build file is both" merge_group "$A" "api_code=true web_app=true" deploy/allinone/Dockerfile
expect "docs are nothing" merge_group "$A" "api_code=false web_app=false web_e2e=false ci_self=false" \
  api/docs/x.md api/changelog.d/x.md web/README.md
expect "env reference is api code" merge_group "$A" "api_code=true" api/docs/configuration/environment-variables.md
expect "own workflow file is ci_self" merge_group "$W" "ci_self=true ci_other=false" .github/workflows/web-ci.yml
expect "another workflow file is ci_other" merge_group "$A" "ci_self=false ci_other=true api_code=false" \
  .github/workflows/web-ci.yml
expect "a script the workflow runs is ci_self" merge_group "$W" "ci_self=true" .github/scripts/changed.sh
expect "a script reached transitively is ci_self" merge_group "$A" "ci_self=true" .github/scripts/go-shard.sh
expect "a data file reached through a script is ci_self" merge_group "$A" "ci_self=true" .github/quarantine.yml
expect "a composite action the workflow uses is ci_self" merge_group "$W" "ci_self=true" .github/actions/go-cache/action.yml
expect "a composite action it does not use is ci_other" merge_group "$A" "ci_self=false ci_other=true" \
  .github/actions/go-cache/action.yml
expect "dependabot config is ci_other" merge_group "$W" "ci_self=false ci_other=true" .github/dependabot.yml
expect "unknown workflow file runs everything CI" merge_group ".github/workflows/missing.yml" "ci_self=true" .github/dependabot.yml
expect "schedule runs everything" schedule "$W" "api_code=true web_app=true web_e2e=true ci_self=true" README.md

# missing MG SHAs
out="$(cd "$d" && GITHUB_OUTPUT=/dev/null GITHUB_EVENT_NAME=merge_group MG_BASE="" MG_HEAD="" WORKFLOW_FILE="$W" bash "$script")"
if grep -q '^web_app=true' <<<"$out" && grep -q '^api_code=true' <<<"$out"; then
  echo "ok:   empty merge_group SHAs run everything"; pass=$((pass + 1))
else
  echo "FAIL: empty merge_group SHAs run everything"; echo "$out"; failed=$((failed + 1))
fi

echo "scope.test.sh: $pass passed, $failed failed"
(( failed == 0 ))
