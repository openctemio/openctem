#!/usr/bin/env bash
# early-warning.sh code | images FILE...
#
# Tells the team about a new high or critical finding on develop the day it
# lands, so it is fixed before a release instead of blocking it. One GitHub
# issue per source, labelled `security` and `early-warning`, opened or updated
# here and closed once the finding is gone. Never fails a build on a finding.
#
#   code    open code-scanning alerts of severity high or critical on develop
#           that main does not have (so what a release would ship), compared
#           with the list the issue recorded last time: alerts that are new
#           since then are named in a comment and marked in the table.
#   images  FILE... are NDJSON reports written by image-guard.sh
#           (IMAGE_GUARD_REPORT): one {"component","target","pkg","installed",
#           "fixed","id","severity","kind"} per fixable HIGH/CRITICAL advisory
#           trivy found in an image of develop.
#
# Env: GH_TOKEN (security-events: read, issues: write), REPO (owner/name),
# SHA (the develop commit, for the text), DEVELOP_REF (default develop),
# MAIN_REF (default main).
#
# Threat model: the issue text carries only rule ids, paths, package names and
# versions taken from GitHub's and trivy's own output, never from a pull
# request's text. Untrusted strings are passed to gh as arguments, not through a
# shell. Nothing here has contents or actions write access.
set -euo pipefail

: "${REPO:?}"
mode="${1:-}"; shift || true
sha="${SHA:-unknown}"
develop="${DEVELOP_REF:-develop}" main="${MAIN_REF:-main}"
ew_label="early-warning"

ensure_labels() {
  gh label create security --description "Security finding or fix" --color d93f0b >/dev/null 2>&1 || true
  gh label create "$ew_label" --description "Opened by the early-warning scan of develop" --color fbca04 >/dev/null 2>&1 || true
}

# find_issue TITLE -> number of the open issue with exactly that title, or "".
find_issue() {
  gh issue list --repo "$REPO" --label "$ew_label" --state open --limit 100 --json number,title 2>/dev/null \
    | jq -r --arg t "$1" '.[] | select(.title == $t) | .number' | head -n 1 || true
}

# issue_state NUMBER -> the numbers/ids recorded in the issue body marker.
recorded() {
  gh issue view "$1" --repo "$REPO" --json body --jq '.body' 2>/dev/null \
    | sed -nE 's/.*<!-- early-warning: (.*) -->.*/\1/p' | head -n 1
}

# report TITLE KEYS_JSON NEW_JSON TABLE_MD: open, update or close.
#   KEYS_JSON  all current keys (JSON array of strings); empty array = clear.
#   NEW_JSON   keys that were not recorded before.
report() {
  local title="$1" keys="$2" new="$3" table="$4" n prior body newn
  ensure_labels
  n="$(find_issue "$title")"
  if [[ "$(jq 'length' <<<"$keys")" -eq 0 ]]; then
    if [[ -n "$n" ]]; then
      gh issue close "$n" --repo "$REPO" --comment "No finding of this kind is left on develop (${sha:0:12})." >/dev/null
      echo "closed #$n"
    else
      echo "nothing to report"
    fi
    return 0
  fi
  prior=""
  [[ -z "$n" ]] || prior="$(recorded "$n")"
  newn="$(jq 'length' <<<"$new")"
  body="$(printf '%s\n\n%s\n\n_Develop at %s. Updated by the early-warning scan; fix these before the next release, the issue closes itself when they are gone._\n\n<!-- early-warning: %s -->' \
    "$title" "$table" "${sha:0:12}" "$(jq -c '.' <<<"$keys")")"
  if [[ -z "$n" ]]; then
    gh issue create --repo "$REPO" --title "$title" --label security --label "$ew_label" --body "$body"
  elif [[ "$(jq -c 'sort' <<<"$keys")" != "$(jq -c 'sort' <<<"${prior:-[]}" 2>/dev/null || echo '[]')" ]]; then
    gh issue edit "$n" --repo "$REPO" --body "$body" >/dev/null
    if [[ "$newn" -gt 0 ]]; then
      gh issue comment "$n" --repo "$REPO" --body "$newn new since the last scan (develop ${sha:0:12}): $(jq -r 'join(", ")' <<<"$new")" >/dev/null
    fi
    echo "updated #$n"
  else
    echo "#$n is current"
  fi
}

case "$mode" in
  code)
    work="$(mktemp -d)"; trap 'find "$work" -delete' EXIT
    fetch() { # fetch <ref> -> open alerts as JSON array
      gh api --paginate "repos/${REPO}/code-scanning/alerts?ref=${1}&state=open&per_page=100" \
        | jq -s 'add // [] | map({number, html_url, sev: (.rule.security_severity_level // ""), rule: .rule.id, path: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line})'
    }
    fetch "refs/heads/${develop}" >"$work/dev.json"
    fetch "refs/heads/${main}" >"$work/main.json"
    jq -n --slurpfile d "$work/dev.json" --slurpfile m "$work/main.json" \
      '($m[0] | map(.number)) as $mn
       | $d[0] | map(select((.sev == "high" or .sev == "critical") and (.number as $x | $mn | index($x) | not)))' >"$work/cur.json"
    keys="$(jq -c 'map(.number | tostring)' "$work/cur.json")"
    n="$(find_issue "Early warning: high or critical code-scanning alerts on develop")"
    prior="[]"; [[ -z "$n" ]] || prior="$(recorded "$n")"; [[ -n "$prior" ]] || prior="[]"
    new="$(jq -c --argjson p "$prior" 'map(select((.number | tostring) as $k | $p | index($k) | not) | .number | tostring)' "$work/cur.json" 2>/dev/null || echo '[]')"
    table="$(jq -r --argjson nw "$new" '
      "| Severity | Rule | Location | Alert | |\n|---|---|---|---|---|\n"
      + (map("| \(.sev) | \(.rule) | `\(.path):\(.line)` | [#\(.number)](\(.html_url)) | \(. as $a | if ($nw | index($a.number | tostring)) then "new" else "" end) |") | join("\n"))' "$work/cur.json")"
    report "Early warning: high or critical code-scanning alerts on develop" "$keys" "$new" "$table"
    ;;
  images)
    [[ $# -gt 0 ]] || { echo "images needs report files" >&2; exit 2; }
    work="$(mktemp -d)"; trap 'find "$work" -delete' EXIT
    cat "$@" 2>/dev/null | jq -s -c 'map(select((.severity == "HIGH" or .severity == "CRITICAL") and ((.fixed // "") != ""))) | unique_by(.component + .pkg + .id)' >"$work/cur.json"
    keys="$(jq -c 'map("\(.component):\(.pkg):\(.id)")' "$work/cur.json")"
    title="Early warning: fixable HIGH or CRITICAL advisories in develop images"
    n="$(find_issue "$title")"
    prior="[]"; [[ -z "$n" ]] || prior="$(recorded "$n")"; [[ -n "$prior" ]] || prior="[]"
    new="$(jq -c --argjson p "$prior" 'map("\(.component):\(.pkg):\(.id)" | select(. as $k | $p | index($k) | not))' "$work/cur.json" 2>/dev/null || echo '[]')"
    table="$(jq -r --argjson nw "$new" '
      "| Image | Package | Installed | Fixed in | Advisory | Severity | |\n|---|---|---|---|---|---|---|\n"
      + (map("| \(.component) | \(.pkg) | \(.installed) | \(.fixed) | \(.id) | \(.severity) | \(. as $a | if ($nw | index("\($a.component):\($a.pkg):\($a.id)")) then "new" else "" end) |") | join("\n"))
      + "\n\nOS packages are fixed by refreshing the base image; application dependencies by bumping them."' "$work/cur.json")"
    report "$title" "$keys" "$new" "$table"
    ;;
  *)
    echo "usage: early-warning.sh code | images FILE..." >&2; exit 2 ;;
esac
