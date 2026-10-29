#!/usr/bin/env bash
# mirror-images.sh: copy the OpenCTEM images of one release into a private
# registry (Harbor, Nexus, GitLab Container Registry, any OCI registry),
# keeping their digests and the release's cosign signatures and attestations.
# Guide: api/docs/deployment/air-gapped.md.
#
#   mirror-images.sh online <version> <dest-prefix> [options]
#       from ghcr.io, or from --source-prefix (a registry proxy of ghcr.io such
#       as a Nexus Docker proxy, or a staging project to promote from)
#   mirror-images.sh bundle <bundle-dir> <dest-prefix> [options]
#       from the release's offline bundle (no internet access needed)
#
# <dest-prefix> is the registry and namespace the images go under, e.g.
# harbor.example.internal/openctem-staging. Each image lands at
# <dest-prefix>/<name>:<version> with the SAME digest as the release.
#
# Options:
#   --images "a b"       only these images (default: every image of the release)
#   --source-prefix P    online mode: read the images from P/<name> instead of
#                        ghcr.io/openctemio/<name> (signatures are checked the
#                        same way: they travel with the images)
#   --source-plain-http  the source registry speaks plain HTTP (lab only)
#   --trusted-root FILE  verify signatures offline against this Sigstore trusted
#                        root (see the guide; required in bundle mode when the
#                        host has no internet access)
#   --plain-http         the destination registry speaks plain HTTP (lab only)
#   --manifest-out FILE  write "<name> <dest ref> <digest>" lines (default:
#                        ./openctem-mirrored-<version>.txt)
#   --env-out FILE       write a Docker Compose .env fragment for these images
#
# Every image is verified BEFORE it is copied (its digest is the one the
# release names, its cosign signature comes from this repository's release
# workflow at the release tag) and AGAIN in the destination (same digest, the
# signature copied with it). A failure stops the run with exit code 1; nothing
# unverified is copied.
#
# Needs: oras (1.2 or later), cosign (2.4 or later), sha256sum, tar; the
# registry login done beforehand (`oras login` / `docker login` share
# ~/.docker/config.json).
set -euo pipefail

ALL_IMAGES="openctem-api openctem-web openctem-console openctem-gateway migrations seed openctem"
SRC_REGISTRY="ghcr.io/openctemio"
REPO_URL="https://github.com/openctemio/openctem"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

usage() { sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'; exit 64; }
die() { echo "mirror-images: $*" >&2; exit 1; }
log() { echo "mirror-images: $*" >&2; }

[ $# -ge 3 ] || usage
mode="$1" src="$2" dest="${3%/}"
shift 3
images="$ALL_IMAGES" trusted_root="" plain_http="" manifest_out="" env_out="" src_plain_http=""
while [ $# -gt 0 ]; do
	case "$1" in
	--images) images="$2"; shift 2 ;;
	--trusted-root) trusted_root="$2"; shift 2 ;;
	--plain-http) plain_http=1; shift ;;
	--source-prefix) SRC_REGISTRY="${2%/}"; shift 2 ;;
	--source-plain-http) src_plain_http=1; shift ;;
	--manifest-out) manifest_out="$2"; shift 2 ;;
	--env-out) env_out="$2"; shift 2 ;;
	-h | --help) usage ;;
	*) die "unknown option $1" ;;
	esac
done

for tool in oras cosign sha256sum tar; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done
case "$dest" in
"" | *" "* | *://*) die "destination '$dest' must look like registry.example.internal/namespace" ;;
esac
[ -z "$trusted_root" ] || [ -r "$trusted_root" ] || die "trusted root $trusted_root is not readable"

dest_flags=()
cosign_dest_flags=()
if [ -n "$plain_http" ]; then
	dest_flags=(--to-plain-http)
	cosign_dest_flags=(--allow-http-registry --allow-insecure-registry)
fi
offline_flags=()
[ -n "$trusted_root" ] && offline_flags=(--offline --trusted-root "$trusted_root")

work="$(mktemp -d "${TMPDIR:-/tmp}/openctem-mirror.XXXXXX")"
trap 'find "$work" -mindepth 1 -delete 2>/dev/null; rmdir "$work" 2>/dev/null || true' EXIT

# verify_image <ref@digest> <workflow> <version> [extra cosign flags]: the
# image is signed by <workflow> of this repository at the release tag.
verify_image() {
	local ref="$1" workflow="$2" version="$3" out
	shift 3
	out="$(cosign verify "$@" ${offline_flags[@]+"${offline_flags[@]}"} \
		--certificate-identity "${REPO_URL}/.github/workflows/${workflow}@refs/tags/${version}" \
		--certificate-oidc-issuer "$OIDC_ISSUER" "$ref" 2>&1)" || {
		printf '%s\n' "$out" >&2
		die "signature check FAILED for $ref (not signed by the $version release workflow)"
	}
}

# verify_blob <file> <bundle> <workflow> <version>
verify_blob() {
	local out
	out="$(cosign verify-blob ${offline_flags[@]+"${offline_flags[@]}"} --bundle "$2" \
		--certificate-identity "${REPO_URL}/.github/workflows/${3}@refs/tags/${4}" \
		--certificate-oidc-issuer "$OIDC_ISSUER" "$1" 2>&1)" || {
		printf '%s\n' "$out" >&2
		die "signature check FAILED for $1"
	}
}

version_ok() {
	case "$1" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "version '$1' is not vX.Y.Z" ;; esac
	case "$1" in *[!0-9A-Za-z.+-]*) die "version '$1' has unexpected characters" ;; esac
}

manifest_lines=()

copy_and_check() { # copy_and_check <name> <version> <digest> <source args...>
	local name="$1" version="$2" digest="$3" got
	shift 3
	local target="${dest}/${name}:${version}"
	oras cp -r "$@" ${dest_flags[@]+"${dest_flags[@]}"} "$target" >/dev/null ||
		die "copy of $name to $target failed"
	local resolve_flags=()
	[ -n "$plain_http" ] && resolve_flags=(--plain-http)
	got="$(oras resolve ${resolve_flags[@]+"${resolve_flags[@]}"} "$target")" || die "cannot resolve $target"
	[ "$got" = "$digest" ] || die "$target has digest $got, the release says $digest"
	verify_image "${dest}/${name}@${digest}" docker-publish.yml "$version" ${cosign_dest_flags[@]+"${cosign_dest_flags[@]}"}
	manifest_lines+=("$name ${dest}/${name}:${version} $digest")
	log "$name: copied to ${dest}/${name}@${digest}, signature verified there"
}

case "$mode" in
online)
	version="$src"
	version_ok "$version"
	src_flags=() cosign_src_flags=()
	if [ -n "$src_plain_http" ]; then
		src_flags=(--from-plain-http)
		cosign_src_flags=(--allow-http-registry --allow-insecure-registry)
	fi
	for name in $images; do
		ref="${SRC_REGISTRY}/${name}:${version}"
		digest="$(oras resolve ${src_plain_http:+--plain-http} "$ref")" || die "cannot resolve $ref"
		verify_image "${SRC_REGISTRY}/${name}@${digest}" docker-publish.yml "$version" ${cosign_src_flags[@]+"${cosign_src_flags[@]}"}
		copy_and_check "$name" "$version" "$digest" ${src_flags[@]+"${src_flags[@]}"} "${SRC_REGISTRY}/${name}@${digest}"
	done
	;;
bundle)
	dir="$src"
	[ -d "$dir" ] || die "bundle directory $dir does not exist"
	list="$(find "$dir" -maxdepth 1 -name 'openctem-images-v*.txt' | head -n 1)"
	[ -n "$list" ] || die "no openctem-images-<version>.txt in $dir"
	version="$(basename "$list" .txt)"
	version="${version#openctem-images-}"
	version_ok "$version"
	[ -r "$list.sigstore.json" ] || die "$list.sigstore.json (its signature) is missing"
	verify_blob "$list" "$list.sigstore.json" docker-publish.yml "$version"
	log "image list $list: signature verified"
	for name in $images; do
		# <name> <source ref> <digest> <archive> <archive sha256>
		line="$(awk -v n="$name" '$1 == n' "$list")"
		[ -n "$line" ] || die "$name is not in $list"
		read -r _ _ digest archive sum <<<"$line"
		case "$archive" in */* | "") die "bad archive name in $list: $archive" ;; esac
		[ -r "$dir/$archive" ] || die "$dir/$archive is missing"
		echo "$sum  $dir/$archive" | sha256sum -c --quiet - || die "$archive does not match its checksum"
		mkdir "$work/$name"
		tar -C "$work/$name" --no-same-owner --no-same-permissions -xf "$dir/$archive"
		copy_and_check "$name" "$version" "$digest" --from-oci-layout "$work/$name:$version"
		find "$work/$name" -mindepth 1 -delete
		rmdir "$work/$name"
	done
	;;
*) usage ;;
esac

manifest_out="${manifest_out:-./openctem-mirrored-${version}.txt}"
printf '%s\n' "# name reference digest (mirror-images.sh $mode, $(date -u +%Y-%m-%dT%H:%M:%SZ))" "${manifest_lines[@]}" >"$manifest_out"
log "wrote $manifest_out"

if [ -n "$env_out" ]; then
	{
		echo "# Docker Compose (api/deploy/.env): OpenCTEM images from ${dest}, release ${version}."
		echo "OPENCTEM_VERSION=${version}"
		for l in "${manifest_lines[@]}"; do
			case "${l%% *}" in
			openctem-api) echo "API_IMAGE=${dest}/openctem-api" ;;
			openctem-web) echo "UI_IMAGE=${dest}/openctem-web" ;;
			openctem-console) echo "CONSOLE_IMAGE=${dest}/openctem-console" ;;
			openctem-gateway) echo "GATEWAY_IMAGE=${dest}/openctem-gateway" ;;
			migrations) echo "MIGRATIONS_IMAGE=${dest}/migrations" ;;
			esac
		done
	} >"$env_out"
	log "wrote $env_out"
fi
