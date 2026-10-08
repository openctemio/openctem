#!/usr/bin/env bash
# Tests for check-customer-identifiers.sh. Run: bash .github/scripts/check-customer-identifiers.test.sh
# Builds throwaway git repositories; touches nothing in this one.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-customer-identifiers.sh"
pass=0 failed=0
lan="192.168.8"; lan="$lan.7" # built, so this file does not trip the check itself

repo() {
  local d; d="$(mktemp -d)"
  git -C "$d" init -q -b main
  git -C "$d" config user.name t; git -C "$d" config user.email t@example.invalid
  echo "$d"
}
put() { mkdir -p "$(dirname "$1/$2")"; printf '%s\n' "$3" > "$1/$2"; git -C "$1" add -A; }

# expect <name> <0|1> <repo> <denylist> [must-contain] [must-not-contain]
expect() {
  local name="$1" want="$2" d="$3" deny="$4" needle="${5:-}" forbidden="${6:-}" out rc=0
  out="$(cd "$d" && CUSTOMER_DENYLIST="$deny" bash "$script" 2>&1)" || rc=$?
  if [[ "$rc" -ne "$want" ]] || [[ -n "$needle" && "$out" != *"$needle"* ]] ||
    [[ -n "$forbidden" && "${out,,}" == *"${forbidden,,}"* ]]; then
    echo "FAIL: $name (exit $rc, want $want)"; echo "$out"; failed=$((failed + 1))
  else
    echo "ok:   $name"; pass=$((pass + 1))
  fi
}

deny=$'acmebank\nWidgets-Corp.example\n\n'

d="$(repo)"; put "$d" src/a.go 'host := "app.example.com"'
expect "clean tree passes" 0 "$d" "$deny"
expect "no secret: skipped with a notice" 0 "$d" "" "skipped"
expect "blank-only secret: skipped, not match-all" 0 "$d" $'\n \n' "holds no patterns"

d="$(repo)"; put "$d" src/a.go 'host := "portal.AcmeBank.example"'
expect "hit fails, case-insensitive, file:line only" 1 "$d" "$deny" "src/a.go:1" "acmebank"

d="$(repo)"; put "$d" docs/x.md $'line one\nsee widgets-corp.example here'
expect "second pattern, line number" 1 "$d" "$deny" "docs/x.md:2" "widgets-corp"

d="$(repo)"; put "$d" seed/acmebank_seed.sql 'select 1;'
expect "file named after a customer fails, name withheld" 1 "$d" "$deny" "withheld" "acmebank"

d="$(repo)"; put "$d" seed/acmebank_seed.sql 'tenant acmebank'
expect "content hit in a denied path withholds the path" 1 "$d" "$deny" "(path withheld):1" "acmebank"

d="$(repo)"; put "$d" web/.env.example "ORIGINS=$lan"
expect "live LAN outside tests fails (even with no secret)" 1 "$d" "" "web/.env.example:1"

d="$(repo)"; put "$d" api/x_test.go "u := \"https://$lan\""; put "$d" web/src/__tests__/y.test.ts "'$lan'"
expect "live LAN in tests is allowed" 0 "$d" "$deny"

d="$(repo)"; put "$d" a.txt 'acmebank'; printf 'acmebank\n' > "$d/untracked.txt"
git -C "$d" commit -qm x; git -C "$d" rm -q --cached a.txt
expect "untracked files are not scanned" 0 "$d" "$deny"

echo "passed $pass, failed $failed"
[[ "$failed" -eq 0 ]]
