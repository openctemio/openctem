#!/usr/bin/env bash
# discover-release.sh: prints the OpenCTEM version to mirror, or nothing when
# there is nothing new.
#   OPENCTEM_VERSION set     -> that version (a manual run or a pinned one)
#   otherwise                -> the latest release from $RELEASE_API_URL
#                               (default: the GitHub API; or your Nexus raw
#                               proxy of https://api.github.com/)
# A version already in $DEST_TRUSTED (openctem-api:<version> resolves) is not
# printed, so a scheduled pipeline is idempotent.
set -euo pipefail
die() { echo "discover-release: $*" >&2; exit 1; }
v="${OPENCTEM_VERSION:-}"
if [ -z "$v" ]; then
	api="${RELEASE_API_URL:-https://api.github.com/repos/openctemio/openctem/releases/latest}"
	v="$(curl -fsSL --proto '=https' --retry 3 "$api" | jq -r '.tag_name')" || die "cannot read $api"
fi
case "$v" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "release '$v' is not vX.Y.Z" ;; esac
case "$v" in *[!0-9A-Za-z.+-]*) die "release '$v' has unexpected characters" ;; esac
if [ -z "${OPENCTEM_FORCE:-}" ] && oras resolve "${DEST_TRUSTED:?}/openctem-api:${v}" >/dev/null 2>&1; then
	echo "discover-release: $v is already in $DEST_TRUSTED" >&2
	exit 0
fi
echo "$v"
