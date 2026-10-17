#!/usr/bin/env bash
# image-guard.sh <component> <image-ref>
#
# Release gates for a built image, run before it is pushed (docker-publish.yml)
# and on every image build of the merge queue (allinone-ci.yml):
#   1. size budget: the image's unpacked layers stay under the component's
#      budget below, so a stray `chown -R`, a second copy of a binary or a
#      build toolchain left in the runtime stage fails the build instead of
#      shipping;
#   2. non-root: the image config names a user that is not root;
#   3. no setuid/setgid file anywhere in the filesystem;
#   4. no HIGH/CRITICAL advisory with a fix in an OS package (trivy): a base
#      image refresh fixes those. Advisories in application dependencies are
#      listed as warnings; govulncheck and npm audit gate them in API/Web CI.
# Needs docker and trivy on PATH.
set -euo pipefail
comp="$1" img="$2"

# Unpacked size budgets in MB (the sum of the image's layers), about 15% above
# the size at the time the budget was set; raise one only with the reason in
# the commit message.
root_ok=""  # set with the reason for a component that must still run as root
case "$comp" in
  openctem-api)     budget=150 ;;  # 131 MB
  openctem-web)     budget=300 ;;  # 253 MB (node alone is ~145 MB)
  openctem-console) budget=260 ;;  # node (~145 MB) + a 59 MB standalone build
  openctem)         budget=560 ;;  # 423 MB + the platform console (~60 MB standalone, RFC-022 rev. 21)
  openctem-gateway) budget=75 ;;   # 63 MB (runs as uid 1000)
  migrations)       budget=25 ;;   # 18 MB
  seed)             budget=25 ;;   # 17 MB
  admin-cli)        budget=40 ;;   # 34 MB at v0.10.0 (WebAuthn + TOTP for console sign-in)
  *) echo "image-guard: no budget for component '$comp'; add one" >&2; exit 2 ;;
esac

fail=0
bad() { echo "::error::image-guard $comp: $*"; fail=1; }

bytes=$(docker history --human=false --format '{{.Size}}' "$img" | awk '{s+=$1} END{print s+0}')
mb=$(( (bytes + 1048575) / 1048576 ))
if [ "$mb" -gt "$budget" ]; then
  bad "unpacked size ${mb} MB exceeds the ${budget} MB budget"
else
  echo "image-guard $comp: size ${mb} MB (budget ${budget} MB)"
fi

user=$(docker image inspect --format '{{.Config.User}}' "$img")
case "${user%%:*}" in
  "" | 0 | root)
    if [ -n "$root_ok" ]; then
      echo "::warning::image-guard $comp: runs as root (allowed: $root_ok)"
    else
      bad "runs as root (USER '${user}'); set a non-root USER"
    fi ;;
  *) echo "image-guard $comp: user ${user}" ;;
esac

c=$(docker create "$img")
suid=$(docker export "$c" | tar -tvf - | awk '$1 ~ /^-..[sS]/ || $1 ~ /^-.....[sS]/ {print $NF}')
docker rm "$c" >/dev/null
if [ -n "$suid" ]; then
  bad "setuid/setgid files: $(echo "$suid" | tr '\n' ' ')"
else
  echo "image-guard $comp: no setuid/setgid files"
fi

if ! trivy image --quiet --scanners vuln --pkg-types os --ignore-unfixed \
  --severity HIGH,CRITICAL --exit-code 1 --format table "$img"; then
  bad "OS packages with fixable HIGH/CRITICAL advisories (refresh the base image)"
fi
lib=$(trivy image --quiet --scanners vuln --pkg-types library --ignore-unfixed \
  --severity HIGH,CRITICAL --format json "$img" |
  jq -r '[.Results[]? | .Target as $t | .Vulnerabilities[]? | "\($t): \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion) \(.VulnerabilityID)"] | unique | .[]')
if [ -n "$lib" ]; then
  echo "::warning::image-guard $comp: application dependencies with fixable HIGH/CRITICAL advisories:"
  echo "$lib"
fi

[ "$fail" = 0 ] && echo "image-guard $comp: OK"
exit "$fail"
