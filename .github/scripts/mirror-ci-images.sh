#!/usr/bin/env bash
# Copy every image listed in .github/ci-images.txt to
# ghcr.io/openctemio/mirror/<name>:<tag> (see that file for why and how).
#
#   bash .github/scripts/mirror-ci-images.sh [list] [registry prefix]
#
# Needs crane on PATH and `crane auth login ghcr.io` done. Idempotent: an image
# whose mirror tag already resolves to the pinned digest is not copied again.
# Exits non-zero when any image could not be mirrored or verified.
set -euo pipefail

list="${1:-.github/ci-images.txt}"
prefix="${2:-ghcr.io/openctemio/mirror}"
here="$(cd "$(dirname "$0")" && pwd)"
failed=0

while read -r src dst _; do
  case "$src" in '' | '#'*) continue ;; esac
  if [[ "$src" != *@sha256:* || -z "$dst" || "$dst" != *:* ]]; then
    echo "::error file=$list::malformed line (want '<source>@sha256:<digest> <name>:<tag>'): $src $dst"
    failed=1
    continue
  fi
  digest="${src##*@}"
  ref="${src%@*}"
  target="$prefix/$dst"

  if [ "$(crane digest "$target" 2>/dev/null || true)" = "$digest" ]; then
    echo "up to date: $target ($digest)"
  else
    sources=("$src")
    # Docker Hub official images are served by public.ecr.aws with the same digests.
    if [[ "$src" == docker.io/library/* ]]; then
      sources+=("public.ecr.aws/docker/library/${src#docker.io/library/}")
    fi
    copied=0
    for s in "${sources[@]}"; do
      if bash "$here/retry.sh" crane copy "$s" "$target"; then
        copied=1
        break
      fi
    done
    if [ "$copied" -ne 1 ]; then
      echo "::error::could not copy $src to $target"
      failed=1
      continue
    fi
  fi

  got="$(crane digest "$target" 2>/dev/null || true)"
  if [ "$got" != "$digest" ]; then
    echo "::error::$target resolves to $got, expected $digest"
    failed=1
    continue
  fi
  echo "mirrored: $target@$digest"

  # Drift report only: the pin stays until someone bumps it on purpose.
  upstream="$(crane digest "$ref" 2>/dev/null || true)"
  if [ -n "$upstream" ] && [ "$upstream" != "$digest" ]; then
    echo "::notice file=$list::$ref now points at $upstream (pinned $digest); bump it when convenient"
  fi
done <"$list"

exit "$failed"
