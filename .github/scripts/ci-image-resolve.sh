#!/usr/bin/env bash
# ci-image-resolve.sh <image> <key>
#
# Prints the digest reference (ghcr.io/openctemio/ci-images/<image>@sha256:...)
# of the CI image for <image> at content <key> when one exists AND its build
# provenance attestation proves that this repository's build-images.yml built
# it on a ref we trust; exits 1 (prints nothing) otherwise, and the caller
# builds the image. A tag is only a lookup hint: what is trusted is the digest
# plus a verified attestation (signer workflow, repository, source ref, not a
# self-hosted runner), so overwriting or planting a tag gains nothing.
#
# Candidates, in order:
#   <key>             pushed by develop or main only; the attestation's source
#                     ref must be refs/heads/develop or refs/heads/main. A
#                     merge-queue or pull-request build never satisfies it.
#   q-<sha>-<key>     pushed by a merge-queue run for commit <sha>. Only tried
#                     when this run is itself a merge-queue run (GITHUB_REF is
#                     refs/heads/gh-readonly-queue/..., GITHUB_SHA is <sha>),
#                     and the attestation's source ref must equal GITHUB_REF
#                     exactly: another queue entry's image is never accepted.
# A pull request never pushes, so it has no candidate of its own.
#
# Environment: REGISTRY (default ghcr.io/openctemio/ci-images), REPO
# (owner/name, default $GITHUB_REPOSITORY), GITHUB_REF and GITHUB_SHA of the
# consumer, GH_TOKEN (for gh attestation verify).
set -euo pipefail
image="${1:?image}" key="${2:?key}"
REGISTRY="${REGISTRY:-ghcr.io/openctemio/ci-images}"
REPO="${REPO:-${GITHUB_REPOSITORY:?REPO or GITHUB_REPOSITORY}}"
signer="${REPO}/.github/workflows/build-images.yml"
trusted_re='^refs/heads/(develop|main)$'
queue_re='^refs/heads/gh-readonly-queue/.+$'

try() { # <tag> <source-ref regex> [<exact source ref>: when given, only this ref matches]
  local tag="$1" re="$2" exact="${3:-}" digest json
  digest="$(docker buildx imagetools inspect "${REGISTRY}/${image}:${tag}" --format '{{.Manifest.Digest}}' 2>/dev/null)" || return 1
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  json="$(gh attestation verify "oci://${REGISTRY}/${image}@${digest}" --repo "$REPO" \
            --signer-workflow "$signer" --deny-self-hosted-runners --format json 2>/dev/null)" || return 1
  # At least one verified attestation was made on a ref matching <re>, for a
  # build of this repository's workflow.
  jq -e --arg re "$re" --arg exact "$exact" --arg repo "$REPO" \
    'any(.[]; (.verificationResult.signature.certificate.sourceRepositoryRef // "") as $r
              | if $exact != "" then $r == $exact else ($r | test($re)) end)
     and all(.[]; (.verificationResult.signature.certificate.sourceRepositoryURI // "") | endswith("/" + $repo))' \
    <<<"$json" >/dev/null || return 1
  echo "${REGISTRY}/${image}@${digest}"
}

try "$key" "$trusted_re" && exit 0
ref="${GITHUB_REF:-}" sha="${GITHUB_SHA:-}"
if [[ "$ref" =~ $queue_re ]]; then
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "ci-image-resolve: bad GITHUB_SHA" >&2; exit 2; }
  try "q-${sha}-${key}" "$queue_re" "$ref" && exit 0
fi
exit 1
