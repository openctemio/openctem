#!/usr/bin/env bash
# Release builds read nothing from shared mutable state: docker-publish.yml
# must not use a registry (or any shared) layer cache, and its service images
# must be pinned by digest. A cache tag in the release packages is writable by
# any job holding packages:write, so its layers would be signed into a release.
set -euo pipefail
f="${1:-.github/workflows/docker-publish.yml}"
rc=0
if grep -nE '^[[:space:]]*cache-(from|to):' "$f"; then
  echo "::error file=$f::release builds must not use cache-from/cache-to (shared mutable layer cache)"
  rc=1
fi
if grep -E '^[[:space:]]*image:[[:space:]]*ghcr\.io/' "$f" | grep -v '@sha256:[0-9a-f]\{64\}'; then
  echo "::error file=$f::pin service images by digest (image: name:tag@sha256:...)"
  rc=1
fi
exit "$rc"
