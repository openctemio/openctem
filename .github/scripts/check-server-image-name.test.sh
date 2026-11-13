#!/usr/bin/env bash
# Self-test of check-server-image-name.sh (a current reference to openctem-api
# fails, a historical or non-image one passes) and of the one helper that maps a
# release to its server image name (deploy/airgap/mirror-images.sh server-image).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
check="$here/check-server-image-name.sh"
work="$(mktemp -d)"
trap 'find "$work" -delete 2>/dev/null || true' EXIT

tree() { # <file> <content>: a new repository holding one tracked file
  local d; d="$(mktemp -d -p "$work")"
  git init -q "$d"; mkdir -p "$d/$(dirname "$1")"
  printf '%s\n' "$2" >"$d/$1"
  git -C "$d" add -A
  echo "$d"
}
expect() { # <want> <name> <file> <content>
  local want="$1" name="$2" d got
  d="$(tree "$3" "$4")"
  if bash "$check" "$d" >/dev/null 2>&1; then got=pass; else got=fail; fi
  [[ "$got" == "$want" ]] || { echo "FAIL: $name: want $want, got $got"; exit 1; }
  echo "ok: $name"
}

expect pass "new name"                         x.yml 'image: ${API_IMAGE:-ghcr.io/openctemio/openctem-server}:v1'
expect fail "compose default"                  x.yml 'image: ${API_IMAGE:-ghcr.io/openctemio/openctem-api}:${OPENCTEM_VERSION}'
expect fail "local CI tag"                     x.yml 'run: docker build -t local/openctem-api:ci server'
expect fail "publish matrix entry"             x.yml '  - { name: openctem-api, legacy: api, context: server }'
expect fail "matrix list"                      x.yml '  name: [openctem-api, openctem-web, migrations]'
expect fail "shell case label"                 x.sh  '  openctem-api) budget=150 ;;'
expect fail "digest pin"                       x.yml '    api: ghcr.io/openctemio/openctem-api@sha256:1111'
expect fail "docs pull line"                   x.md  'docker pull ghcr.io/openctemio/openctem-api:vX.Y.Z'
expect pass "names an old release"             x.md  'docker pull ghcr.io/openctemio/openctem-api:v0.22.0'
expect pass "names the old line"               x.md  'published as `openctem-api` up to v0.22.x'
expect pass "names the boundary"               x.md  'openctem-api is the name before v0.23.0'
expect pass "accepts both names"               x.sh  'for n in openctem-server openctem-api; do'
expect pass "Prometheus job label"             x.yml 'expr: up{job="openctem-api"} == 0'
expect pass "Prometheus job in JSON"           x.json '"expr": "max(ingest_queue_depth{job=\"openctem-api\"})"'
expect pass "Prometheus scrape job"            x.sh  '  - job_name: openctem-api'
expect pass "Kubernetes object names"          x.md  'kubectl create secret generic openctem-api-secrets and t-openctem-api-admin'
expect pass "kubectl deployment"               x.md  'kubectl exec -it deploy/openctem-api -n openctem -- sh'
expect pass "changelog history"                server/CHANGELOG.md '- image ghcr.io/openctemio/openctem-api:vX.Y.Z'
expect pass "upgrade guide"                    server/docs/operations/upgrade-v0.8-to-v0.9.md 'ghcr.io/openctemio/openctem-api'
expect pass "marker"                           x.md  'ghcr.io/openctemio/openctem-api  <!-- image-name: allow -->'
expect pass "all-in-one Unix account"          deploy/allinone/Dockerfile ' && addgroup -S -g 1002 openctem-api \'
expect fail "all-in-one build arg"             deploy/allinone/Dockerfile '#     --build-arg API_IMAGE=ghcr.io/openctemio/openctem-api:vX.Y.Z \'

# The release -> server image name helper.
name() { bash "$root/deploy/airgap/mirror-images.sh" server-image "$1" 2>/dev/null; }
want() { # <version> <name>
  local got; got="$(name "$1" || echo refused)"
  [[ "$got" == "$2" ]] || { echo "FAIL: server-image $1: want $2, got $got"; exit 1; }
  echo "ok: server-image $1 -> $2"
}
want v0.9.0 openctem-api
want v0.22.0 openctem-api
want v0.22.17 openctem-api
want v0.23.0 openctem-server
want v0.23.0-rc.1 openctem-server
want v0.23.1 openctem-server
want v0.100.0 openctem-server
want v1.0.0 openctem-server
want v1.5.0 openctem-server
want latest refused
want 'v0.23.0;id' refused

echo "all check-server-image-name tests passed"
