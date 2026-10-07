#!/usr/bin/env bash
#
# generate-in-docker.sh — write the generated contract files into a checkout
# using only Docker (no Go or Node on the host). `make generate-docker` runs it.
#
# The files are generated, never committed (api/docs/development/ci-cd.md,
# "Generated contract files"):
#
#   api/api/openapi/swagger.yaml               OpenAPI spec (swag)
#   api/api/openapi/routes.txt                 registered routes
#   web/src/config/api-route-permissions.json  web route permission map
#   web/src/lib/api/generated/api.types.ts     web API types (from the spec)
#
# Use it on a host that runs the stack from a bind-mounted checkout (next dev +
# air): after `git pull` the files are absent or stale until this runs.
#
# Two throwaway containers, each with the checkout mounted:
#   1. golang (the version api/Dockerfile builds with): `make -C api contract`.
#   2. node (the version web/Dockerfile ships): installs web/'s locked
#      dependencies INSIDE the container (the checkout's node_modules is not
#      touched) and converts the spec to TypeScript.
# Caches live in the named volumes openctem-gen-gomod, openctem-gen-gobuild and
# openctem-gen-npm, so later runs are quick. The written files are handed to
# the checkout's owner.
#
# Usage:
#   scripts/generate-in-docker.sh [CHECKOUT]     (default: this repository)
#
# Exit codes: 0 = generated, 1 = a step failed, 2 = usage.

set -euo pipefail

ROOT="$(cd "${1:-$(dirname "$0")/..}" && pwd)"
if [ ! -f "$ROOT/api/go.mod" ] || [ ! -f "$ROOT/web/package-lock.json" ]; then
  echo "generate-in-docker: $ROOT is not an openctem checkout (api/go.mod, web/package-lock.json)" >&2
  exit 2
fi
command -v docker >/dev/null || { echo "generate-in-docker: docker is required" >&2; exit 2; }

# Same images as the Dockerfiles, so generation matches the image builds.
go_image="$(awk '/^FROM golang:/ {print $2; exit}' "$ROOT/api/Dockerfile")"
node_image="$(awk '/^FROM node:/ {print $2; exit}' "$ROOT/web/Dockerfile")"
[ -n "$go_image" ] && [ -n "$node_image" ] || { echo "generate-in-docker: cannot read the base images from the Dockerfiles" >&2; exit 1; }

owner="$(stat -c '%u:%g' "$ROOT")"
outputs=(
  api/api/openapi/swagger.yaml
  api/api/openapi/routes.txt
  web/src/config/api-route-permissions.json
  web/src/lib/api/generated/api.types.ts
)

echo "generate-in-docker: Go half in $go_image"
docker run --rm \
  -v "$ROOT:/src" \
  -v openctem-gen-gomod:/go/pkg/mod \
  -v openctem-gen-gobuild:/root/.cache/go-build \
  -e GOWORK=off -e GOTOOLCHAIN=local \
  -e GOFLAGS="-buildvcs=false -p=2" -e GOMAXPROCS="${GOMAXPROCS:-2}" \
  -e OWNER="$owner" \
  -w /src \
  "$go_image" sh -euc '
    apk add --no-cache make >/dev/null
    make -C api contract
    chown "$OWNER" api/api/openapi/swagger.yaml api/api/openapi/routes.txt web/src/config/api-route-permissions.json
  '

echo "generate-in-docker: web API types in $node_image"
docker run --rm \
  -v "$ROOT:/src" \
  -v openctem-gen-npm:/root/.npm \
  -e OWNER="$owner" \
  "$node_image" sh -euc '
    apk add --no-cache bash >/dev/null
    mkdir -p /work/scripts
    cp /src/web/package.json /src/web/package-lock.json /src/web/.prettierrc /work/
    cp /src/web/scripts/generate-api-types.sh /work/scripts/
    cd /work
    npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
    OPENAPI_SPEC=/src/api/api/openapi/swagger.yaml bash scripts/generate-api-types.sh
    out=/src/web/src/lib/api/generated/api.types.ts
    mkdir -p "$(dirname "$out")"
    cp src/lib/api/generated/api.types.ts "$out"
    chown "$OWNER" "$out"
  '

for f in "${outputs[@]}"; do
  [ -s "$ROOT/$f" ] || { echo "generate-in-docker: $f was not written" >&2; exit 1; }
done
echo "generate-in-docker: wrote ${outputs[*]}"
