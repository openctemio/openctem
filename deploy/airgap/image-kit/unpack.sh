#!/usr/bin/env bash
# unpack.sh <assets-dir> <version> [--arches "amd64 arm64"] [--trusted-root FILE]
#
# Verifies the release archives in <assets-dir> and unpacks them under
# ./dist/<arch>/<component>/ of this kit, where the Dockerfiles copy from.
# Guide: api/docs/deployment/air-gapped.md ("Build images from the release
# archives").
#
#   1. checksums-sha256.txt must carry a valid Sigstore signature from this
#      repository's Release workflow at the tag <version>
#      (checksums-sha256.txt.sigstore.json; cosign verify-blob);
#   2. every archive used must match its line in checksums-sha256.txt.
# Nothing is unpacked unless both pass. --trusted-root verifies offline
# against a Sigstore trusted root you copied in (see the guide).
set -euo pipefail

die() { echo "unpack: $*" >&2; exit 1; }
[ $# -ge 2 ] || die "usage: unpack.sh <assets-dir> <version> [--arches \"amd64 arm64\"] [--trusted-root FILE]"
assets="$1" version="$2"
shift 2
arches="amd64 arm64" trusted_root=""
while [ $# -gt 0 ]; do
	case "$1" in
	--arches) arches="$2"; shift 2 ;;
	--trusted-root) trusted_root="$2"; shift 2 ;;
	*) die "unknown option $1" ;;
	esac
done
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "version '$version' is not vX.Y.Z" ;; esac
case "$version" in *[!0-9A-Za-z.+-]*) die "version '$version' has unexpected characters" ;; esac
for t in cosign sha256sum tar; do command -v "$t" >/dev/null 2>&1 || die "$t is not installed"; done

kit="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sums="$assets/checksums-sha256.txt"
{ [ -r "$sums" ] && [ -r "$sums.sigstore.json" ]; } || die "$sums and $sums.sigstore.json are required"

offline=()
[ -n "$trusted_root" ] && offline=(--offline --trusted-root "$trusted_root")
cosign verify-blob ${offline[@]+"${offline[@]}"} --bundle "$sums.sigstore.json" \
	--certificate-identity "https://github.com/openctemio/openctem/.github/workflows/release.yml@refs/tags/${version}" \
	--certificate-oidc-issuer https://token.actions.githubusercontent.com "$sums" >/dev/null ||
	die "checksums-sha256.txt is NOT signed by the ${version} release workflow"
echo "unpack: checksums-sha256.txt signature verified (release.yml@refs/tags/${version})"

for arch in $arches; do
	case "$arch" in amd64 | arm64) ;; *) die "arch $arch is not amd64 or arm64" ;; esac
	for comp in server gateway web console; do
		archive="openctem-${comp}-${version}-linux-${arch}.tar.gz"
		[ -r "$assets/$archive" ] || die "$assets/$archive is missing"
		line="$(awk -v f="$archive" '$2 == f || $2 == "./" f || $2 == "*" f' "$sums")"
		[ -n "$line" ] || die "$archive is not listed in checksums-sha256.txt"
		echo "${line%% *}  $assets/$archive" | sha256sum -c --quiet - || die "$archive does not match its checksum"
		dest="$kit/dist/$arch/$comp"
		[ ! -e "$dest" ] || die "$dest exists; remove $kit/dist first"
		mkdir -p "$dest"
		tar -C "$dest" --strip-components=1 --no-same-owner -xzf "$assets/$archive"
		echo "unpack: $archive -> dist/$arch/$comp"
	done
done
