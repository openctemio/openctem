#!/usr/bin/env bash
# Guard for the server image name. The server image is
# ghcr.io/openctemio/openctem-server from v0.23.0; releases v0.9.0 to v0.22.x
# were published as openctem-api, which keeps those tags and receives no new
# ones. Fails when a tracked file names openctem-api where it would mean the
# image of a current release, so the old name cannot come back by habit.
#
# What is NOT a hit (the allow-list):
#   - a line that also names openctem-server (it maps or accepts both names),
#     a release up to v0.22.x (v0.9.0, v0.22.x, ...) or v0.23.0 (the
#     boundary): the reference explains which releases it means;
#   - Prometheus job labels (job="openctem-api", job_name: openctem-api): a
#     scrape job name, not an image;
#   - Kubernetes object names (openctem-api-secrets, t-openctem-api,
#     deploy/openctem-api in a kubectl line): Helm resource names, not images;
#   - released history and decision records: every CHANGELOG.md, the changelog
#     fragments, the version upgrade guides (server/docs/operations/upgrade-*.md)
#     and the RFCs;
#   - the PATHS entries below (file + line pattern): Unix accounts of the
#     all-in-one image, an OIDC audience in a test, a Prometheus rule group;
#   - a line that carries the marker "image-name: allow".
#
# The one place that maps a release to its server image name for tools that
# handle older releases is `deploy/airgap/mirror-images.sh server-image <v>`.
#
# Usage: check-server-image-name.sh [repo-root]   (default: the repository root)
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$root"

excludes=(
  ':(exclude,glob)**/CHANGELOG.md'
  ':(exclude,glob)server/changelog.d/**'
  ':(exclude,glob)server/docs/operations/upgrade-*.md'
  ':(exclude,glob)server/docs/rfcs/**'
  ':(exclude)scripts/rename/backend-dir.sh'
  ':(exclude).github/scripts/check-server-image-name.sh'
  ':(exclude).github/scripts/check-server-image-name.test.sh'
  ':(exclude,glob)**/node_modules/**'
  ':(exclude,glob)**/package-lock.json'
)

# <path>|<ERE>: a hit in <path> whose line matches <ERE> is not the image.
PATHS=(
  'deploy/allinone/Dockerfile|addgroup|adduser|^# nextjs = web'
  'deploy/allinone/supervise.sh|openctem-api:openctem-api|openctem-signer:openctem-api|^[[:space:]]*# openctem-api, setgid'
  'server/docs/deployment/docker.md|^\| API \| 1002 `openctem-api`'
  'server/pkg/keycloak/validator_test.go|"aud"|validator\(t, "openctem-api"\)|raw\("account", "openctem-api"\)'
  'deploy/observability/prometheus/rules/openctem.yml|^[[:space:]]*- name: openctem-api$'
)

# The name as a word: not part of a longer name (t-openctem-api,
# openctem-api-secrets, openctem-apis).
hits="$(git grep -nIP -e '(?<![A-Za-z0-9_-])openctem-api(?![A-Za-z0-9_-])' -- . "${excludes[@]}" 2>/dev/null || true)"

line_ok() { # <text>
  local t="$1"
  [[ "$t" == *openctem-server* ]] && return 0
  [[ "$t" == *"image-name: allow"* ]] && return 0
  grep -qE 'v0\.([0-9]|1[0-9]|2[0-2])\.[0-9x]|v0\.23\.0' <<<"$t" && return 0
  grep -qE 'job[a-z_]*\\?"?[[:space:]]*(=~|!~|=|:)[[:space:]]*\\?"?[^,}]*openctem-api' <<<"$t" && return 0
  grep -qE 'kubectl .*(deploy|job|secret)[^ ]*/?openctem-api' <<<"$t" && return 0
  return 1
}
path_ok() { # <file> <text>
  local e p re
  for e in "${PATHS[@]}"; do
    p="${e%%|*}" re="${e#*|}"
    [[ "$1" == "$p" ]] && grep -qE "$re" <<<"$2" && return 0
  done
  return 1
}

bad=()
while IFS= read -r h; do
  [[ -n "$h" ]] || continue
  file="${h%%:*}" rest="${h#*:}" text="${rest#*:}"
  line_ok "$text" && continue
  path_ok "$file" "$text" && continue
  bad+=("$h")
done <<<"$hits"

if ((${#bad[@]})); then
  echo "::error::the server image is openctem-server from v0.23.0: these lines name openctem-api without saying which older releases they mean (name v0.22.x or earlier on the line, or use openctem-server)"
  printf '%s\n' "${bad[@]}" | head -n 40
  exit 1
fi
echo "server image name: no stale openctem-api references"
