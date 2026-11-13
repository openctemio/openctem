#!/usr/bin/env bash
# =============================================================================
# image-diff-ci.sh <base-commit>: the image-diff gate of the api/ -> server/
# rename (research/414 §5), run by .github/workflows/rename-image-diff.yml.
#
# Builds the API image (target production) and the migrations image twice with
# the same build arguments: from <base-commit> (still laid out as api/) and from
# the checked-out tree (server/), then compares them with image-diff.sh. Skips
# (exit 0) unless the base has api/go.mod and the tree has server/go.mod, so it
# is inert on every pull request except the rename itself and branches caught
# up across it.
# =============================================================================
set -euo pipefail
base="${1:?usage: image-diff-ci.sh <base-commit>}"
root="$(git rev-parse --show-toplevel)"
cd "$root"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! git cat-file -e "$base:api/go.mod" 2>/dev/null || [ ! -f server/go.mod ]; then
  echo "image-diff: not a rename change (base without api/go.mod or tree without server/go.mod); skipped"
  exit 0
fi
work="$(mktemp -d)"
cleanup() {
  git worktree remove --force "$work/before" >/dev/null 2>&1 || true
  docker rmi -f imgdiff/api:before imgdiff/api:after imgdiff/migrations:before imgdiff/migrations:after >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
git worktree add -q --detach "$work/before" "$base"
want=v0.0.0-imagediff
args=(--build-arg "VERSION=$want" --build-arg COMMIT=0000000 --build-arg BUILD_TIME=2026-01-01T00:00:00Z)
build() { # <tag> <context> [extra args]
  local tag="$1" ctx="$2"; shift 2
  echo "image-diff: building $tag"
  docker buildx build --load -q -t "$tag" "${args[@]}" "$@" "$ctx" >/dev/null
}
build imgdiff/api:before "$work/before/api" --target production
build imgdiff/api:after server --target production
build imgdiff/migrations:before "$work/before/api" -f "$work/before/api/Dockerfile.migrations"
build imgdiff/migrations:after server -f server/Dockerfile.migrations
fail=0
echo "== server image (openctem-server)"
WANT_VERSION="$want" ALLOW_CONTENT="/app/api/openapi/swagger.yaml /app/third-party-notices.json" \
  bash "$here/image-diff.sh" imgdiff/api:before imgdiff/api:after /app/server /app/openctem-signer /app/openctem-migrate || fail=1
echo "== migrations image"
WANT_VERSION="$want" bash "$here/image-diff.sh" imgdiff/migrations:before imgdiff/migrations:after /usr/local/bin/openctem-migrate || fail=1
echo "== OpenAPI spec as data (paths, operations and definition names)"
docker create --name imgdiff-spec-a imgdiff/api:before >/dev/null; docker create --name imgdiff-spec-b imgdiff/api:after >/dev/null
docker cp imgdiff-spec-a:/app/api/openapi/swagger.yaml "$work/a.yaml"; docker cp imgdiff-spec-b:/app/api/openapi/swagger.yaml "$work/b.yaml"
docker rm -f imgdiff-spec-a imgdiff-spec-b >/dev/null
python3 - "$work/a.yaml" "$work/b.yaml" <<'PY' || fail=1
import sys, yaml
a, b = (yaml.safe_load(open(p)) for p in sys.argv[1:3])
ok = True
def strip(x):
    # description texts may cite a repository path; list order is not stable in swag
    if isinstance(x, dict): return {k: strip(v) for k, v in x.items() if k != "description"}
    if isinstance(x, list): return sorted((strip(v) for v in x), key=repr)
    return x
for part in ("paths", "definitions"):
    if set(a[part]) != set(b[part]):
        print(f"FAIL {part}: keys differ: {sorted(set(a[part]) ^ set(b[part]))[:10]}"); ok = False
    elif strip(a[part]) != strip(b[part]):
        print(f"FAIL {part}: content differs beyond descriptions"); ok = False
    else:
        print(f"ok   {part}: {len(a[part])} keys, same content (descriptions aside)")
sys.exit(0 if ok else 1)
PY
echo "== route manifest and route permission map (generated from each tree)"
for t in "$work/before/api" server; do
  (cd "$t" && GOWORK=off UPDATE_ROUTE_MANIFEST=1 go test ./tools/lint/openapicontract/ -run '^TestWriteRouteManifest$' -count=1 >/dev/null \
    && GOWORK=off UPDATE_ROUTE_PERMISSIONS=1 go test ./tests/unit -run '^TestRoutePermissionMap$' -count=1 >/dev/null)
done
if cmp -s "$work/before/api/api/openapi/routes.txt" server/api/openapi/routes.txt; then
  echo "ok   routes.txt identical ($(wc -l < server/api/openapi/routes.txt) routes)"
else
  echo "FAIL routes.txt differs:"; diff "$work/before/api/api/openapi/routes.txt" server/api/openapi/routes.txt | head -n 20; fail=1
fi
if cmp -s "$work/before/web/src/config/api-route-permissions.json" web/src/config/api-route-permissions.json; then
  echo "ok   api-route-permissions.json identical"
else
  echo "FAIL api-route-permissions.json differs"; fail=1
fi
[ "$fail" = 0 ] && echo "image-diff: PASS" || echo "image-diff: FAIL"
exit "$fail"
