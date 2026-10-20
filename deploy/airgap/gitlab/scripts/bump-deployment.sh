#!/usr/bin/env bash
# bump-deployment.sh <version> <mirrored-list>: opens a merge request in your
# deployment repository that pins the new release's images by digest.
#
# Writes, on a new branch openctem-<version>:
#   $BUMP_DIR/openctem-images.yaml  Helm values (repository, tag, digest)
#   $BUMP_DIR/openctem-images.env   Docker Compose fragment (repositories, tag)
# Needs: git, curl, jq; CI variables
#   DEPLOY_PROJECT_ID   numeric id of the deployment project
#   DEPLOY_REPO_URL     its https clone URL (without credentials)
#   DEPLOY_TOKEN        project access token: role Developer, scopes
#                       write_repository + api, on that project ONLY
#   BUMP_DIR            directory in that repository (default: openctem)
#   DEPLOY_TARGET_BRANCH  branch the merge request targets (default: main)
set -euo pipefail
die() { echo "bump-deployment: $*" >&2; exit 1; }
{ [ $# -eq 2 ] && [ -r "$2" ]; } || die "usage: bump-deployment.sh <version> <mirrored-list>"
version="$1" list="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
: "${DEPLOY_PROJECT_ID:?}" "${DEPLOY_REPO_URL:?}" "${DEPLOY_TOKEN:?}"
case "$DEPLOY_REPO_URL" in https://*) ;; *) die "DEPLOY_REPO_URL must be https://" ;; esac
dir="${BUMP_DIR:-openctem}"
branch="openctem-${version}"

repo_of() { awk -v n="$1" '$1 == n { r = $2; sub(/:[^:\/]*$/, "", r); print r }' "$list"; }
digest_of() { awk -v n="$1" '$1 == n { print $3 }' "$list"; }

work="$(mktemp -d)"
trap 'find "$work" -mindepth 1 -delete 2>/dev/null; rmdir "$work" 2>/dev/null || true' EXIT
# The token goes in a header, never into the URL or the git config on disk.
auth="Authorization: Basic $(printf 'oauth2:%s' "$DEPLOY_TOKEN" | base64 -w0)"
git -c "http.extraHeader=$auth" clone --quiet --depth 1 "$DEPLOY_REPO_URL" "$work/repo"
cd "$work/repo"
git checkout --quiet -b "$branch"
mkdir -p "$dir"

image_block() { # image_block <name>
	printf '      repository: %s\n      tag: %s\n      digest: %s\n' "$(repo_of "$1")" "$version" "$(digest_of "$1")"
}
{
	echo "# OpenCTEM ${version}: images from the trusted registry project, pinned by digest."
	echo "# Written by bump-deployment.sh from the verified mirror list."
	echo "api:"
	echo "  image:"
	image_block openctem-api | sed 's/^  //'
	echo "  migrations:"
	echo "    image:"
	image_block migrations
	echo "ui:"
	echo "  image:"
	image_block openctem-web | sed 's/^  //'
	echo "console:"
	echo "  image:"
	image_block openctem-console | sed 's/^  //'
	echo "gateway:"
	echo "  caddy:"
	echo "    image:"
	image_block openctem-gateway
} >"$dir/openctem-images.yaml"
{
	echo "OPENCTEM_VERSION=${version}"
	echo "API_IMAGE=$(repo_of openctem-api)"
	echo "UI_IMAGE=$(repo_of openctem-web)"
	echo "CONSOLE_IMAGE=$(repo_of openctem-console)"
	echo "GATEWAY_IMAGE=$(repo_of openctem-gateway)"
	echo "MIGRATIONS_IMAGE=$(repo_of migrations)"
} >"$dir/openctem-images.env"

git add "$dir/openctem-images.yaml" "$dir/openctem-images.env"
git -c user.name="openctem-mirror" -c user.email="openctem-mirror@invalid" \
	commit --quiet -m "openctem: ${version} (images pinned by digest)"
git -c "http.extraHeader=$auth" push --quiet origin "$branch"
api="${CI_API_V4_URL:?}/projects/${DEPLOY_PROJECT_ID}/merge_requests"
body="$(jq -n --arg s "$branch" --arg b "${DEPLOY_TARGET_BRANCH:-main}" --arg t "OpenCTEM ${version}" \
	--arg d "Images mirrored from the ${version} release, signatures verified, scanned. Digests: see $dir/openctem-images.yaml." \
	'{source_branch: $s, target_branch: $b, title: $t, description: $d, remove_source_branch: true}')"
curl -fsS --proto '=https' -H "PRIVATE-TOKEN: ${DEPLOY_TOKEN}" -H 'Content-Type: application/json' \
	-d "$body" "$api" | jq -r '.web_url'
