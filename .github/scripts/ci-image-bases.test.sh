#!/usr/bin/env bash
# Self-test of ci-image-bases.sh: only digest-pinned bases of the allow-listed
# upstreams are mirrored, under a digest tag; anything else is skipped.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="$(mktemp -d)"
trap 'find "$dir" -mindepth 1 -delete; rmdir "$dir"' EXIT

d1=sha256:$(printf 'a%.0s' {1..64})
d2=sha256:$(printf 'b%.0s' {1..64})
d3=sha256:$(printf 'c%.0s' {1..64})
cat >"$dir/Dockerfile" <<DF
FROM --platform=\$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26.9-alpine@$d1 AS builder
FROM gcr.io/distroless/static-debian12:nonroot@$d2
FROM public.ecr.aws/docker/library/python:3.12-slim AS unpinned
FROM ghcr.io/someone/else:1@$d3
FROM docker.io/library/alpine:3@$d3
FROM builder AS final
DF
cat >"$dir/Dockerfile.other" <<DF
FROM public.ecr.aws/docker/library/golang:1.26.9-alpine@$d1
FROM public.ecr.aws/docker/library/Bad:tag@$d3
DF

got="$(bash "$here/ci-image-bases.sh" "$dir/Dockerfile" "$dir/Dockerfile.other" 2>/dev/null)"
want="gcr.io/distroless/static-debian12:nonroot@$d2 distroless/static-debian12:sha256-${d2#sha256:}
docker.io/library/golang:1.26.9-alpine@$d1 golang:sha256-${d1#sha256:}"
if [ "$got" != "$want" ]; then
  printf 'ci-image-bases.sh output:\n%s\nwant:\n%s\n' "$got" "$want" >&2
  exit 1
fi
echo "ci-image-bases.sh: ok"
