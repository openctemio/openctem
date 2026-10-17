#!/usr/bin/env bash
# Tests for check-private-keys.sh. Run: bash .github/scripts/check-private-keys.test.sh
# Builds throwaway git repositories; touches nothing in this one. The key blocks are
# assembled at run time so this file never holds one.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-private-keys.sh"
pass=0 failed=0
dash="-----"
block() { printf '%sBEGIN %sPRIVATE KEY%s\nMHcCAQEEIFakeFakeFakeFakeFakeFakeFakeFakeFake\n%sEND %sPRIVATE KEY%s\n' "$dash" "$1" "$dash" "$dash" "$1" "$dash"; }

# case <name> <want rc> <path> <content>  (staged and range modes are both checked)
check() {
  local name="$1" want="$2" path="$3" content="$4" d rc
  d="$(mktemp -d)"
  git -C "$d" init -q -b main
  git -C "$d" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m base
  mkdir -p "$d/$(dirname "$path")"; printf '%s' "$content" > "$d/$path"
  git -C "$d" add -f "$path"
  rc=0; (cd "$d" && bash "$script" --staged >/dev/null 2>&1) || rc=$?
  [[ "$rc" -eq "$want" ]] || { echo "FAIL: $name (staged, exit $rc, want $want)"; failed=$((failed + 1)); return; }
  git -C "$d" -c user.name=t -c user.email=t@example.invalid commit -q -m add
  rc=0; (cd "$d" && bash "$script" HEAD~1 HEAD >/dev/null 2>&1) || rc=$?
  [[ "$rc" -eq "$want" ]] || { echo "FAIL: $name (range, exit $rc, want $want)"; failed=$((failed + 1)); return; }
  echo "ok:   $name"; pass=$((pass + 1))
}

check "pem key fails"            1 api/x.txt            "$(block '')"
check "rsa key fails"            1 api/x.txt            "$(block 'RSA ')"
check "openssh key fails"        1 deploy/x.txt         "$(block 'OPENSSH ')"
check "ec key fails"             1 data/sensor-ca/a.pem "$(block 'EC ')"
check "any file under data fails" 1 data/notes.txt      "hello"
check ".key file fails"          1 certs/server.key     "x"
check ".p12 file fails"          1 certs/a.p12          "x"
check ".pfx file fails"          1 certs/a.pfx          "x"
check "id_ed25519 fails"         1 ssh/id_ed25519       "x"
check "testdata key allowed"     0 api/pkg/a/testdata/k.pem "$(block '')"
check "testdata .key allowed"    0 api/pkg/a/testdata/s.key "x"
check "header-only placeholder passes" 0 web/a.tsx "placeholder=\"${dash}BEGIN RSA PRIVATE KEY${dash}\""
check "go string with escaped newline passes" 0 api/a_test.go "x := \"${dash}BEGIN PRIVATE KEY${dash}\\nAAAA\\n\""
check "public cert passes"       0 deploy/ca.crt "$(printf '%sBEGIN CERTIFICATE%s\nMIIBFakeFakeFakeFakeFakeFakeFake\n%sEND CERTIFICATE%s\n' "$dash" "$dash" "$dash" "$dash")"
check "plain file passes"        0 api/main.go "package main"

echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
