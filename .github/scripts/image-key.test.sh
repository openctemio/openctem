#!/usr/bin/env bash
# Tests for image-key.sh: a key moves with exactly the inputs of its image.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'find "$tmp" -delete' EXIT
cd "$tmp"
git init -q . && git config user.email t@example.invalid && git config user.name t
mkdir -p api/deploy/gateway web deploy/allinone .github/actions/generate-contract docs
for f in api/a.go api/deploy/gateway/g web/w.ts deploy/allinone/d .github/actions/generate-contract/action.yml docs/x.md; do echo 1 > "$f"; done
git add -A && git commit -qm base
K() { bash "$here/image-key.sh" "$1"; }
declare -A base; for i in api admin-cli web console allinone; do base[$i]="$(K $i)"; done
fail=0
chk() { # <what> <image> <expect same|diff>
  local now; now="$(K "$2")"
  if { [ "$3" = same ] && [ "$now" = "${base[$2]}" ]; } || { [ "$3" = diff ] && [ "$now" != "${base[$2]}" ]; }; then :; else echo "FAIL: $1: $2 expected $3"; fail=1; fi
}
[ "${#base[api]}" = 40 ] || { echo "FAIL: key is not 40 chars"; fail=1; }
[ "${base[api]}" != "${base[admin-cli]}" ] || { echo "FAIL: api and admin-cli share a key"; fail=1; }
[ "${base[web]}" != "${base[console]}" ] || { echo "FAIL: web and console share a key"; fail=1; }

echo 2 > docs/x.md; git commit -qam docs
for i in api admin-cli web console allinone; do chk "docs change" $i same; done

echo 2 > web/w.ts; git commit -qam web
chk "web change" api same; chk "web change" admin-cli same
chk "web change" web diff; chk "web change" console diff; chk "web change" allinone diff
for i in api admin-cli web console allinone; do base[$i]="$(K $i)"; done

echo 2 > api/a.go; git commit -qam api
chk "api change" api diff; chk "api change" admin-cli diff
chk "api change" web diff   # the contract is generated from api
chk "api change" allinone diff
for i in api admin-cli web console allinone; do base[$i]="$(K $i)"; done

echo 2 > deploy/allinone/d; git commit -qam allinone
chk "allinone change" api same; chk "allinone change" web same; chk "allinone change" allinone diff

# An empty commit (same tree) keeps every key: the key is content, not history.
for i in api admin-cli web console allinone; do base[$i]="$(K $i)"; done
git commit -q --allow-empty -m empty
for i in api admin-cli web console allinone; do chk "empty commit" $i same; done
bash "$here/image-key.sh" nope 2>/dev/null && { echo "FAIL: unknown image accepted"; fail=1; }
[ "$fail" = 0 ] && echo "image-key: ok"
exit "$fail"
