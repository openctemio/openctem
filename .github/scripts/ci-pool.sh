#!/usr/bin/env bash
# ci-pool.sh: which runner pool a workflow run's heavy jobs use.
# Env: RUN_ID (github.run_id), SHARE (vars.CI_SELFHOSTED_SHARE, percent).
# Prints and appends `pool=openctem-ci|ubuntu-latest` to $GITHUB_OUTPUT.
# See .github/actions/ci-pool/action.yml. Tests: ci-pool.test.sh.
set -euo pipefail
share="${SHARE:-}"
if ! [[ "$share" =~ ^[0-9]{1,3}$ ]] || (( 10#$share > 100 )); then share=20; fi
run_id="${RUN_ID:-}"
if ! [[ "$run_id" =~ ^[0-9]+$ ]]; then run_id=0; share=0; fi
if (( 10#$run_id % 100 < 10#$share )); then pool=openctem-ci; else pool=ubuntu-latest; fi
echo "pool=$pool (run $run_id mod 100 = $((10#$run_id % 100)), share $share%)" >&2
echo "pool=$pool" >> "${GITHUB_OUTPUT:-/dev/stdout}"
