#!/usr/bin/env bash
# release-preflight.sh [--ref REF] [--main BRANCH] [--images FILE] [--no-fetch]
#
# What would stop (or surprise) the next release, before anyone cuts it. Prints a
# Markdown report (also appended to $GITHUB_STEP_SUMMARY) and exits 1 when there
# is a blocker. Runs in the release train's Plan job and locally, from a clone
# with the tags:
#
#   GH_TOKEN=$(gh auth token) REPO=openctemio/openctem bash .github/scripts/release-preflight.sh
#
#   1. code scanning: open alerts on develop that main does not have.
#      high/critical are blockers (the early-warning issue lists them as they
#      appear); medium are listed as warnings.
#   2. images: the fixable HIGH/CRITICAL advisories image-guard.sh found in the
#      images of develop. OS packages are blockers (a base image refresh fixes
#      them, and image-guard would fail the release build), application
#      dependencies are warnings. The report is --images FILE (IMAGE_GUARD_REPORT
#      format) or, when absent, the newest `image-guard-report` artifact of
#      this repository; without either the section says "not available".
#   3. migrations: the numbers added since the last release tag, and a blocker
#      for a duplicate number or one below the highest number of that tag
#      (golang-migrate silently skips it on every migrated database), through
#      check-migration-versions.sh.
#
# --ref is the commit to release (default origin/develop). Env: REPO (default
# the origin remote), GH_TOKEN (security-events: read; actions: read for the
# image report). A source that cannot be read is reported, never a pass.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release/lib.sh
source "$HERE/release/lib.sh"

ref="origin/develop" main="main" images="" fetch=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) ref="$2"; shift ;;
    --main) main="$2"; shift ;;
    --images) images="$2"; shift ;;
    --no-fetch) fetch=0 ;;
    -h|--help) awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

repo="${REPO:-$(git config --get remote.origin.url 2>/dev/null | sed -E 's#^(git@github.com:|https://github.com/)##; s#\.git$##')}"
[[ -n "$repo" ]] || { echo "set REPO=owner/name" >&2; exit 2; }
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
blockers=0 warnings=0
work="$(mktemp -d)"; trap 'find "$work" -delete' EXIT

out() { printf '%s\n' "$*" | tee -a "$summary"; }
blocker() { blockers=$((blockers + 1)); out "- BLOCKER: $*"; }
warning() { warnings=$((warnings + 1)); out "- warning: $*"; }
[[ $fetch -eq 0 ]] || git fetch --quiet --tags origin >/dev/null 2>&1 || true

out "## Release preflight"
out ""
out "Release candidate: \`$ref\` ($(git rev-parse --short "$ref" 2>/dev/null || echo unknown))."

# 1. Code scanning ---------------------------------------------------------------
out ""
out "### Code scanning (open on develop, absent from $main)"
alerts() { # alerts <branch> -> JSON array or fails
  gh api --paginate "repos/${repo}/code-scanning/alerts?ref=refs/heads/${1}&state=open&per_page=100" 2>/dev/null \
    | jq -s 'add // [] | map({number, html_url, sev: (.rule.security_severity_level // ""), rule: .rule.id, path: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line})'
}
if alerts develop >"$work/dev.json" && alerts "$main" >"$work/main.json" && [[ -s "$work/dev.json" ]]; then
  jq -n --slurpfile d "$work/dev.json" --slurpfile m "$work/main.json" \
    '($m[0] | map(.number)) as $mn | $d[0] | map(select((.sev | IN("medium","high","critical")) and (.number as $x | $mn | index($x) | not)))' >"$work/new.json"
  nb="$(jq '[.[] | select(.sev == "high" or .sev == "critical")] | length' "$work/new.json")"
  nm="$(jq '[.[] | select(.sev == "medium")] | length' "$work/new.json")"
  if [[ "$nb" -eq 0 && "$nm" -eq 0 ]]; then
    out "- none"
  else
    [[ "$nb" -eq 0 ]] || blocker "$nb high or critical alert(s)"
    [[ "$nm" -eq 0 ]] || warning "$nm medium alert(s)"
    out ""
    out "| Severity | Rule | Location | Alert |"
    out "|---|---|---|---|"
    jq -r 'sort_by(.sev) | .[] | "| \(.sev) | \(.rule) | `\(.path):\(.line)` | [#\(.number)](\(.html_url)) |"' "$work/new.json" | tee -a "$summary"
  fi
else
  blocker "code-scanning alerts could not be read (token needs security-events: read); the result is unknown"
fi

# 2. Images -------------------------------------------------------------------------
out ""
out "### Images (fixable HIGH/CRITICAL, from image-guard)"
if [[ -z "$images" ]]; then
  # Only a run of develop in this repository counts: a pull request or merge
  # queue run can upload an artifact of the same name with its own content.
  id="$(gh api "repos/${repo}/actions/artifacts?name=image-guard-report&per_page=50" \
    --jq '[.artifacts[] | select(.expired == false and .workflow_run.head_branch == "develop"
      and .workflow_run.head_repository_id == .workflow_run.repository_id)][0].id // empty' 2>/dev/null || true)"
  if [[ -n "$id" ]] && gh api "repos/${repo}/actions/artifacts/${id}/zip" >"$work/report.zip" 2>/dev/null \
    && unzip -p "$work/report.zip" >"$work/report.ndjson" 2>/dev/null; then
    images="$work/report.ndjson"
    out "(artifact $id, the newest build of develop that scanned its images)"
  fi
fi
if [[ -z "$images" || ! -f "$images" ]]; then
  out "- not available (no --images file and no \`image-guard-report\` artifact); the release build runs image-guard itself"
else
  jq -s -c 'map(select((.severity == "HIGH" or .severity == "CRITICAL") and ((.fixed // "") != ""))) | unique_by(.component + .pkg + .id)' "$images" >"$work/img.json" 2>/dev/null || echo '[]' >"$work/img.json"
  no="$(jq '[.[] | select(.kind == "os")] | length' "$work/img.json")"
  nl="$(jq '[.[] | select(.kind != "os")] | length' "$work/img.json")"
  if [[ "$no" -eq 0 && "$nl" -eq 0 ]]; then
    out "- none"
  else
    [[ "$no" -eq 0 ]] || blocker "$no fixable advisory(ies) in OS packages (refresh the base image)"
    [[ "$nl" -eq 0 ]] || warning "$nl fixable advisory(ies) in application dependencies"
    out ""
    out "| Image | Package | Installed | Fixed in | Advisory | Severity | Kind |"
    out "|---|---|---|---|---|---|---|"
    jq -r '.[] | "| \(.component) | \(.pkg) | \(.installed) | \(.fixed) | \(.id) | \(.severity) | \(.kind) |"' "$work/img.json" | tee -a "$summary"
  fi
fi

# 3. Migrations ----------------------------------------------------------------------
out ""
last="$(rel_latest_tag .)"
out "### Migrations since ${last:-the beginning}"
if [[ -z "$last" ]]; then
  out "- no release tag; skipped"
else
  added="$(git diff --name-only --diff-filter=A --no-renames "${last}" "${ref}" -- 'api/migrations/*.up.sql' 2>/dev/null | sed -E 's#.*/([0-9]+)_.*#\1#' | sort -n | tr '\n' ' ')"
  if [[ -z "${added// /}" ]]; then
    out "- none added"
  else
    out "- added: ${added}"
  fi
  # The versions guard reads the working tree: it is meaningful when the checkout is the candidate.
  if [[ "$(git rev-parse HEAD 2>/dev/null)" == "$(git rev-parse "$ref" 2>/dev/null)" ]]; then
    if guard="$(bash "$HERE/check-migration-versions.sh" "$last" 2>&1)"; then
      out "- version guard: OK (no duplicate, nothing below ${last}'s highest)"
    else
      blocker "migration versions: $(grep -E '^::error::' <<<"$guard" | sed 's/^::error:://' | tr '\n' ' ')"
    fi
  else
    out "- version guard not run (the checkout is not $ref)"
  fi
fi

# 4. Release lines --------------------------------------------------------------------
# versions.yaml's "latest" of each sensor product, the SDK and the CI runner is
# what a platform release installs without the release feed: the bundled
# sensor's Compose default, the chart's sensor tag and the install snippets of
# an instance that cannot reach the feed. It moves forward when a platform
# release is cut (versions.yaml header), so one behind the published release
# is a blocker: the release would install an old sensor.
out ""
out "### Release lines (versions.yaml latest vs the published releases)"
manifest="$work/versions.yaml"
if ! git show "${ref}:versions.yaml" >"$manifest" 2>/dev/null; then
  out "- no versions.yaml at $ref; skipped"
else
  # SECTION=REPO: every product section names its image (ghcr.io/openctemio/<repo>).
  lines="sdk=sdk-go ci=ci"
  while IFS= read -r section; do
    image="$(rel_yaml_get "$manifest" "$section.image" 2>/dev/null || true)"
    [[ "$image" == ghcr.io/openctemio/* ]] && lines="$lines $section=${image#ghcr.io/openctemio/}"
  done < <(grep -E '^[a-z0-9][a-z0-9-]*:[[:space:]]*(#.*)?$' "$manifest" | sed 's/:.*//')
  for pair in $lines; do
    section="${pair%%=*}" product_repo="${pair#*=}"
    have="$(rel_yaml_get "$manifest" "$section.latest" 2>/dev/null || true)"
    [[ -n "$have" ]] || continue
    published="$(gh api "repos/openctemio/${product_repo}/releases/latest" --jq .tag_name 2>/dev/null || true)"
    if ! rel_is_version "$published"; then
      warning "${section}: the latest release of openctemio/${product_repo} could not be read; versions.yaml says ${have}"
    elif rel_version_gt "$published" "$have"; then
      blocker "${section}.latest is ${have}, openctemio/${product_repo} published ${published}: set it in versions.yaml and run .github/scripts/release/sync-versions.sh"
    else
      out "- ${section}: ${have} (current)"
    fi
  done
fi

out ""
if [[ "$blockers" -gt 0 ]]; then
  out "**Preflight: ${blockers} blocker(s), ${warnings} warning(s).**"
  exit 1
fi
out "**Preflight: no blockers, ${warnings} warning(s).**"
exit 0
