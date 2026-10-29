#!/usr/bin/env bash
# Tests for pr-no-package-write.sh on fixture workflow directories.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'find "$tmp" -delete' EXIT
fail=0
mk() { mkdir -p "$tmp/$1"; cat > "$tmp/$1/$2"; }
chk() { # <dir> <expect pass|fail> <what>
  if bash "$here/pr-no-package-write.sh" "$tmp/$1" >/dev/null 2>&1; then r=pass; else r=fail; fi
  [ "$r" = "$2" ] || { echo "FAIL: $3 (got $r)"; fail=1; }
}
mk callee build.yml <<'Y'
on: workflow_call
jobs:
  b:
    runs-on: ubuntu-latest
    permissions: {contents: read, packages: write}
    steps: [{run: "true"}]
Y
# a PR workflow calling the write workflow, unguarded
mk bad1 build.yml < "$tmp/callee/build.yml"
mk bad1 ci.yml <<'Y'
on: [pull_request]
jobs:
  images:
    uses: ./.github/workflows/build.yml
Y
chk bad1 fail "unguarded call of a packages: write workflow on pull_request"
# its own write permission, unguarded
mk bad2 ci.yml <<'Y'
on: {pull_request: {}, push: {}}
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    permissions: {packages: write}
    steps: [{run: "true"}]
Y
chk bad2 fail "job with packages: write on pull_request"
# inherited write-all
mk bad3 ci.yml <<'Y'
on: pull_request_target
permissions: write-all
jobs:
  j: {runs-on: ubuntu-latest, steps: [{run: "true"}]}
Y
chk bad3 fail "workflow-level write-all on pull_request_target"
# guarded
mk ok1 build.yml < "$tmp/callee/build.yml"
mk ok1 ci.yml <<'Y'
on: [pull_request, push]
jobs:
  images:
    if: github.event_name != 'pull_request'
    uses: ./.github/workflows/build.yml
  images-pr:
    if: github.event_name == 'pull_request'
    permissions: {contents: read, packages: read}
    uses: ./.github/workflows/build.yml
Y
chk ok1 fail "read-only caller of a write workflow: the callee cannot exceed it, but images-pr must not call it"
mk ok2 build.yml < "$tmp/callee/build.yml"
mk ok2 ci.yml <<'Y'
on: [pull_request, push]
jobs:
  images:
    if: github.event_name != 'pull_request'
    uses: ./.github/workflows/build.yml
Y
chk ok2 pass "guarded write call"
# a push-only workflow may write
mk ok3 pub.yml <<'Y'
on: push
jobs:
  j: {runs-on: ubuntu-latest, permissions: {packages: write}, steps: [{run: "true"}]}
Y
chk ok3 pass "push-only workflow"
# the repository's real workflows
bash "$here/pr-no-package-write.sh" "$here/../workflows" || fail=1
[ "$fail" = 0 ] && echo "pr-no-package-write: tests ok"
exit "$fail"
