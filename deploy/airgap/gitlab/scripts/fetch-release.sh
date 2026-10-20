#!/usr/bin/env bash
# fetch-release.sh <version> <out-dir> <file>...
#
# Downloads release assets of openctemio/openctem <version> from
# $RELEASES_BASE_URL (default: GitHub; set it to your Nexus raw proxy, e.g.
# https://nexus.example.internal/repository/github-openctemio/openctem/releases/download),
# always with checksums-sha256.txt and its Sigstore bundle, then verifies:
#   1. the checksums file is signed by the release workflow at <version>;
#   2. every requested file matches its checksum.
# Exits non-zero and leaves no unverified file behind on any failure.
# COSIGN_TRUSTED_ROOT (optional): verify offline against this trusted root.
set -euo pipefail
die() { echo "fetch-release: $*" >&2; exit 1; }
[ $# -ge 2 ] || die "usage: fetch-release.sh <version> <out-dir> <file>..."
version="$1" out="$2"
shift 2
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "version '$version' is not vX.Y.Z" ;; esac
case "$version" in *[!0-9A-Za-z.+-]*) die "version '$version' has unexpected characters" ;; esac
base="${RELEASES_BASE_URL:-https://github.com/openctemio/openctem/releases/download}"
mkdir -p "$out"
tmp="$(mktemp -d "$out/.fetch.XXXXXX")"
trap 'find "$tmp" -mindepth 1 -delete 2>/dev/null; rmdir "$tmp" 2>/dev/null || true' EXIT

get() {
	case "$1" in */* | "") die "bad asset name '$1'" ;; esac
	curl -fsSL --proto '=https' --retry 3 -o "$tmp/$1" "$base/$version/$1" || die "download of $1 failed"
}
get checksums-sha256.txt
get checksums-sha256.txt.sigstore.json
offline=()
[ -n "${COSIGN_TRUSTED_ROOT:-}" ] && offline=(--offline --trusted-root "$COSIGN_TRUSTED_ROOT")
cosign verify-blob ${offline[@]+"${offline[@]}"} --bundle "$tmp/checksums-sha256.txt.sigstore.json" \
	--certificate-identity "https://github.com/openctemio/openctem/.github/workflows/release.yml@refs/tags/${version}" \
	--certificate-oidc-issuer https://token.actions.githubusercontent.com "$tmp/checksums-sha256.txt" >/dev/null 2>&1 ||
	die "checksums-sha256.txt of $version is NOT signed by the release workflow"
for f in "$@"; do
	get "$f"
	line="$(awk -v f="$f" '$2 == f || $2 == "./" f || $2 == "*" f' "$tmp/checksums-sha256.txt")"
	[ -n "$line" ] || die "$f is not listed in checksums-sha256.txt"
	(cd "$tmp" && echo "${line%% *}  $f" | sha256sum -c --quiet -) || die "$f does not match its checksum"
done
find "$tmp" -maxdepth 1 -type f -exec mv -t "$out" {} +
echo "fetch-release: $version: checksums signature and $# file(s) verified into $out"
