#!/usr/bin/env bash
# ci-image-resolve.sh <image> <key> [<pr-number>]
#
# Prints the digest reference (ghcr.io/openctemio/ci-images/<image>@sha256:...)
# of the CI image for <image> at content <key> when one exists AND its build
# provenance attestation proves that this repository's build-images.yml built
# it on a ref we trust; exits 1 (prints nothing) otherwise, and the caller
# builds the image. A tag is only a lookup hint: what is trusted is the digest
# plus a verified attestation, so overwriting or planting a tag gains nothing.
#
# Candidates, in order:
#   <key>           pushed by develop, main or a merge-queue run (trusted refs);
#                   the attestation's source ref must be refs/heads/develop,
#                   refs/heads/main or refs/heads/gh-readonly-queue/...
#   pr<N>-<key>     pushed by pull request N's own runs; the source ref must be
#                   refs/pull/<N>/merge. Only given when <pr-number> is set.
#
# Environment: REGISTRY (default ghcr.io/openctemio/ci-images), REPO
# (owner/name, default $GITHUB_REPOSITORY), GH_TOKEN (for gh attestation verify).
set -euo pipefail
image="${1:?image}" key="${2:?key}" pr="${3:-}"
REGISTRY="${REGISTRY:-ghcr.io/openctemio/ci-images}"
REPO="${REPO:-${GITHUB_REPOSITORY:?REPO or GITHUB_REPOSITORY}}"
signer="${REPO}/.github/workflows/build-images.yml"
trusted_re='^refs/heads/(develop|main|gh-readonly-queue/.+)$'

try() { # <tag> <source-ref regex>
  local tag="$1" re="$2" digest json
  digest="$(docker buildx imagetools inspect "${REGISTRY}/${image}:${tag}" --format '{{.Manifest.Digest}}' 2>/dev/null)" || return 1
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  json="$(gh attestation verify "oci://${REGISTRY}/${image}@${digest}" --repo "$REPO" \
            --signer-workflow "$signer" --format json 2>/dev/null)" || return 1
  # At least one verified attestation was made on a ref matching <re>, for a
  # build of this repository's workflow.
  jq -e --arg re "$re" --arg repo "$REPO" \
    'any(.[]; (.verificationResult.signature.certificate.sourceRepositoryRef // "") | test($re))
     and all(.[]; (.verificationResult.signature.certificate.sourceRepositoryURI // "") | endswith("/" + $repo))' \
    <<<"$json" >/dev/null || return 1
  echo "${REGISTRY}/${image}@${digest}"
}

try "$key" "$trusted_re" && exit 0
if [ -n "$pr" ]; then
  [[ "$pr" =~ ^[0-9]+$ ]] || { echo "ci-image-resolve: bad PR number" >&2; exit 2; }
  try "pr${pr}-${key}" "^refs/pull/${pr}/merge\$" && exit 0
fi
exit 1
