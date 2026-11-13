#!/usr/bin/env bash
# Runs `make -C server swagger` in the same image and with the same packages
# scripts/generate-in-docker.sh uses for its Go half (the golang alpine image of
# server/Dockerfile plus the `apk add` list of that script), so a recipe that
# needs a tool this image lacks (perl, bash, python, jq) fails here and not on
# an operator's source checkout. No product image is built.
# Usage: swagger-in-alpine.sh [repo-root]    DRY_RUN=1 prints the command only.
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
image="$(awk '/^FROM .*golang:/ { for (i = 1; i <= NF; i++) if ($i ~ /^golang:/) { print $i; exit } }' "$root/server/Dockerfile")"
pkgs="$(sed -n 's/^[[:space:]]*apk add --no-cache \(.*\) >\/dev\/null$/\1/p' "$root/scripts/generate-in-docker.sh" | head -n 1)"
[[ -n "$image" && -n "$pkgs" ]] || { echo "swagger-in-alpine: cannot read the image or the apk list" >&2; exit 1; }
cmd=(docker run --rm -v "$root:/src" -w /src
  -e GOWORK=off -e GOTOOLCHAIN=local -e GOFLAGS="-buildvcs=false -p=2" -e CGO_ENABLED=0
  "$image" sh -euc "apk add --no-cache $pkgs >/dev/null; make -C server swagger; test -s server/api/openapi/swagger.yaml")
if [[ "${DRY_RUN:-}" == 1 ]]; then printf '%q ' "${cmd[@]}"; echo; exit 0; fi
"${cmd[@]}"
