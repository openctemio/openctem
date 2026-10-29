#!/usr/bin/env bash
# Self-test of check-runners.sh: the approved selectors pass, anything that
# could send a fork pull request (or a merge group) to a self-hosted runner,
# or an unknown runner, fails.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/check-runners.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0

FORK="(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)"
MERGE="(github.event_name == 'merge_group' && (vars.CI_RUNNER_MERGE || 'ubuntu-latest'))"
LIGHT="\${{ $MERGE || ($FORK && vars.CI_RUNNER_LIGHT) || 'ubuntu-latest' }}"
POOL="needs.changes.outputs.pool"
MERGEP="(github.event_name == 'merge_group' && (vars.CI_RUNNER_MERGE || $POOL || 'ubuntu-latest'))"
HEAVYV="($FORK && (vars.CI_RUNNER_HEAVY || $POOL))"
HEAVY="\${{ $MERGEP || $HEAVYV || 'ubuntu-latest' }}"
CODEQL="\${{ ($FORK && vars.CI_RUNNER_CODEQL) || $MERGEP || $HEAVYV || 'ubuntu-latest' }}"
E2E="\${{ ($FORK && vars.CI_RUNNER_E2E_BUILD) || $MERGEP || $HEAVYV || 'ubuntu-latest' }}"

case_() { # name want-rc runs-on [extra file text]
  local d="$tmp/$1"
  mkdir -p "$d"
  printf 'on: pull_request\njobs:\n  a:\n    runs-on: %s\n    steps:\n      - run: true\n%s' "$3" "${4:-}" >"$d/w.yml"
  local rc=0
  bash "$script" "$d" >"$d/out" 2>&1 || rc=$?
  [ -n "${VERBOSE:-}" ] && sed "s/^/    /" "$d/out"
  if [ "$rc" != "$2" ]; then
    echo "FAIL: $1 (exit $rc, want $2)"; sed 's/^/  /' "$d/out"; fails=$((fails + 1))
  else
    echo "ok: $1"
  fi
}

case_ hosted-literal 0 'ubuntu-latest'
case_ hosted-quoted 0 '"ubuntu-24.04"'
case_ light 0 "$LIGHT"
case_ light-extra-spaces 0 "\${{  $MERGE ||   ($FORK && vars.CI_RUNNER_LIGHT) || 'ubuntu-latest'   }}"
case_ heavy 0 "$HEAVY"
case_ codeql 0 "$CODEQL"
case_ e2e-build 0 "$E2E"
case_ matrix-hosted 0 '${{ matrix.runner }}' $'    strategy:\n      matrix:\n        include:\n          - { arch: amd64, runner: ubuntu-latest }\n          - { arch: arm64, runner: ubuntu-24.04-arm }\n'

case_ self-hosted-literal 1 'self-hosted'
case_ label-literal 1 'openctem-ci'
case_ list-form 1 '[self-hosted, linux]'
case_ multi-line 1 ''
case_ matrix-self-hosted 1 '${{ matrix.runner }}' $'    strategy:\n      matrix:\n        runner: [ubuntu-latest, openctem-ci]\n'
case_ matrix-unresolved 1 '${{ matrix.runner }}'
# A fork pull request would reach the self-hosted runner.
case_ no-fork-guard 1 "\${{ $MERGE || vars.CI_RUNNER_LIGHT || 'ubuntu-latest' }}"
case_ var-only 1 '${{ vars.CI_RUNNER_LIGHT }}'
case_ var-or-hosted 1 "\${{ vars.CI_RUNNER_LIGHT || 'ubuntu-latest' }}"
# A merge group would take the light runner without CI_RUNNER_MERGE.
case_ light-in-merge-group 1 "\${{ ($FORK && vars.CI_RUNNER_LIGHT) || 'ubuntu-latest' }}"
# Unknown variable or context.
case_ unknown-var 1 "\${{ $MERGE || ($FORK && vars.CI_RUNNER_OTHER) || 'ubuntu-latest' }}"
case_ input 1 "\${{ inputs.runner || 'ubuntu-latest' }}"
# The pool output must not bypass the fork guard or reach a light job.
case_ pool-no-fork-guard 1 "\${{ $MERGEP || vars.CI_RUNNER_HEAVY || $POOL || 'ubuntu-latest' }}"
case_ pool-without-fallback-in-merge 1 "\${{ (github.event_name == 'merge_group' && (vars.CI_RUNNER_MERGE || $POOL)) || $HEAVYV || 'ubuntu-latest' }}"
case_ pool-in-light 1 "\${{ $MERGE || ($FORK && (vars.CI_RUNNER_LIGHT || $POOL)) || 'ubuntu-latest' }}"
case_ pool-bare 1 "\${{ $POOL }}"
case_ pool-other-job 1 "\${{ $MERGE || ($FORK && (vars.CI_RUNNER_HEAVY || needs.other.outputs.pool)) || 'ubuntu-latest' }}"
# Safe but not one of the approved forms: refused, so every job reads the same.
case_ unapproved-safe 1 "\${{ $MERGE || 'ubuntu-latest' }}"

# The repository's own workflows pass.
rc=0
(cd "$here/../.." && bash "$script" >/dev/null) || rc=$?
if [ "$rc" != 0 ]; then echo "FAIL: repository workflows (exit $rc)"; fails=$((fails + 1)); else echo "ok: repository workflows"; fi

if [ "$fails" -gt 0 ]; then echo "$fails failure(s)"; exit 1; fi
echo "all check-runners cases pass"
