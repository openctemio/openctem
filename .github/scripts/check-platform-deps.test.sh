#!/usr/bin/env bash
# Self-test of check-platform-deps.sh: a clean tree passes, and each kind of
# forbidden dependency fails it.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
check="$here/check-platform-deps.sh"
work="$(mktemp -d)"
trap 'find "$work" -delete 2>/dev/null || true' EXIT

clean_tree() {
  local d="$1"
  mkdir -p "$d/api/internal/x" "$d/web/src/lib"
  cat >"$d/api/go.mod" <<'EOF'
module github.com/openctemio/openctem/api

go 1.26.0

require (
	github.com/openctemio/ctis v1.6.0
	github.com/openctemio/ctis/transfer v0.1.0
)
EOF
  printf 'github.com/openctemio/ctis v1.6.0 h1:x=\n' >"$d/api/go.sum"
  cat >"$d/api/internal/x/x.go" <<'EOF'
package x

import (
	"github.com/openctemio/ctis/transfer"
)

// A comment naming github.com/openctemio/sdk-go is not an import.
var _ = transfer.Stats{}
EOF
  printf '{"dependencies":{"react":"19.0.0"}}\n' >"$d/web/package.json"
  printf "import { x } from '@/lib/x'\n" >"$d/web/src/lib/a.ts"
}

expect() {
  local want="$1" name="$2" d="$3"
  if bash "$check" "$d" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $name: want $want, got $got"
    exit 1
  fi
  echo "ok: $name"
}

n=0
case_dir() { n=$((n + 1)); local d="$work/$n"; clean_tree "$d"; echo "$d"; }

d="$(case_dir)"; expect pass "clean tree" "$d"

d="$(case_dir)"
printf 'require github.com/openctemio/sdk-go v0.33.0\n' >>"$d/api/go.mod"
expect fail "go.mod requires sdk-go" "$d"

d="$(case_dir)"
printf 'require github.com/openctemio/sdk-go/pkg/transfer v0.1.0\n' >>"$d/api/go.mod"
expect fail "go.mod requires an sdk-go nested module" "$d"

d="$(case_dir)"
printf 'replace github.com/openctemio/sensor => ../sensor\n' >>"$d/api/go.mod"
expect fail "go.mod replaces the sensor" "$d"

d="$(case_dir)"
printf 'github.com/openctemio/sdk-go v0.33.0/go.mod h1:y=\n' >>"$d/api/go.sum"
expect fail "go.sum carries sdk-go (indirect)" "$d"

d="$(case_dir)"
printf 'package x\n\nimport "github.com/openctemio/sdk-go/pkg/jobsig"\n' >"$d/api/internal/x/y.go"
expect fail "single import of sdk-go" "$d"

d="$(case_dir)"
printf 'package x\n\nimport (\n\tsdk "github.com/openctemio/sensor/internal/x"\n)\n' >"$d/api/internal/x/y.go"
expect fail "aliased import of the sensor in a block" "$d"

d="$(case_dir)"
printf 'package x\n\nimport (\n\t"github.com/openctemio/connector-tenable/pkg/x"\n)\n' >"$d/api/internal/x/y.go"
expect fail "import of a connector product" "$d"

d="$(case_dir)"
printf '{"dependencies":{"@openctemio/sdk":"1.0.0"}}\n' >"$d/web/package.json"
expect fail "web depends on an SDK package" "$d"

d="$(case_dir)"
printf "import { y } from '@openctemio/sensor-types'\n" >"$d/web/src/lib/b.ts"
expect fail "web imports a sensor package" "$d"

echo "check-platform-deps self-test: all cases passed"
