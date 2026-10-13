#!/usr/bin/env bash
# Print, in the .github/ci-images.txt format, every digest-pinned base image
# of the given Dockerfiles that the CI image mirror serves to the other
# openctemio repositories (their builds swap the base for its mirror copy:
# sensor and asset-collector scripts/ci-mirror-contexts.sh).
#
#   bash .github/scripts/ci-image-bases.sh Dockerfile [Dockerfile...]
#
# Mirrored upstreams (any other FROM is skipped):
#   public.ecr.aws/docker/library/<name>:<tag>@<digest>
#       -> docker.io/library/<name>:<tag>@<digest>   mirror/<name>:sha256-<hex>
#   gcr.io/distroless/<name>:<tag>@<digest>
#       -> gcr.io/distroless/<name>:<tag>@<digest>   mirror/distroless/<name>:sha256-<hex>
#
# The mirror tag is the digest itself, so a bump in one repository never
# moves a tag another repository or ci-images.txt pins; consumers pull by
# digest from the same mirror repository. A Docker Hub source falls back to
# public.ecr.aws in mirror-ci-images.sh (same digests).
set -euo pipefail

name_re='[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*'
tag_re='[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}'

grep -hoE '^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?[^[:space:]]+@sha256:[0-9a-f]{64}' "$@" \
  | awk '{print $NF}' | LC_ALL=C sort -u | while read -r ref; do
  digest="${ref##*@}"
  image="${ref%@*}"
  case "$image" in
    public.ecr.aws/docker/library/*)
      path="${image#public.ecr.aws/docker/library/}"
      src="docker.io/library/$path"
      dst_prefix=""
      ;;
    gcr.io/distroless/*)
      path="${image#gcr.io/distroless/}"
      src="$image"
      dst_prefix="distroless/"
      ;;
    *) continue ;;
  esac
  name="${path%:*}"
  tag="${path##*:}"
  if [[ "$path" != *:* || ! "$name" =~ ^${name_re}$ || ! "$tag" =~ ^${tag_re}$ ]]; then
    echo "::warning::skipping base image with an unexpected reference: $ref" >&2
    continue
  fi
  echo "$src@$digest $dst_prefix$name:sha256-${digest#sha256:}"
done
