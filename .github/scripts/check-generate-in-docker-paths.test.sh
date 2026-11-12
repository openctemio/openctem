#!/usr/bin/env bash
# Self-test of check-generate-in-docker-paths.sh on a small throwaway tree.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
check="$here/check-generate-in-docker-paths.sh"
work="$(mktemp -d)"
trap 'find "$work" -delete 2>/dev/null || true' EXIT

mk() { # <spec-path-in-script> [recipe]: a tree whose script names that OPENAPI_SPEC
  local d; d="$(mktemp -d -p "$work")"
  mkdir -p "$d/scripts" "$d/server/api/openapi" "$d/web/scripts" "$d/web/src/config" "$d/web/src/lib/api/generated"
  : >"$d/server/go.mod"; : >"$d/server/Dockerfile"; : >"$d/server/api/openapi/undocumented-routes.txt"
  printf 'swagger:\n\t@%s\ncontract: swagger\n\t@true\n' "${2:-sed s/a/b/ x}" >"$d/server/Makefile"
  : >"$d/web/package.json"; : >"$d/web/package-lock.json"; : >"$d/web/Dockerfile"; : >"$d/web/scripts/generate-api-types.sh"
  : >"$d/web/src/config/keep"; : >"$d/web/src/lib/api/generated/keep"
  cat >"$d/scripts/generate-in-docker.sh" <<S
ROOT=x
[ ! -f "\$ROOT/server/go.mod" ] || [ ! -f "\$ROOT/web/package-lock.json" ]
outputs=(
  server/api/openapi/swagger.yaml
  web/src/lib/api/generated/api.types.ts
)
apk add --no-cache make >/dev/null
make -C server contract
cp /src/web/package.json /work/
OPENAPI_SPEC=$1 bash scripts/generate-api-types.sh
S
  git init -q "$d"; git -C "$d" add -A; echo "$d"
}
expect() { # <want> <name> <spec> [recipe]
  local want="$1" name="$2"
  local d got; d="$(mk "$3" "${4:-}")"
  if bash "$check" "$d" >/dev/null 2>&1; then got=pass; else got=fail; fi
  [[ "$got" == "$want" ]] || { echo "FAIL: $name: want $want, got $got"; exit 1; }
  echo "ok: $name"
}
expect pass "spec in server/"          "/src/server/api/openapi/swagger.yaml"
expect fail "spec under the old api/"  "/src/api/api/openapi/swagger.yaml"
expect fail "swagger recipe uses perl"   "/src/server/api/openapi/swagger.yaml" "perl -pi -e s/a/b/ f"
expect pass "swagger recipe uses sed"    "/src/server/api/openapi/swagger.yaml" "sh scripts/x.sh f"
echo "all check-generate-in-docker-paths tests passed"
