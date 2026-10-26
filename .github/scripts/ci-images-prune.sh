#!/usr/bin/env bash
# ci-images-prune.sh select <versions.json> <protected-digests.txt> <days> [<now-epoch>]
# ci-images-prune.sh run    (the scheduled workflow: lists, selects, deletes)
#
# Retention for ghcr.io/openctemio/ci-images/*: delete package versions older
# than <days> (default 14), except a version whose digest (its `name`) is in
# the protected list: images an open release refers to. Untagged versions
# (attestations, replaced tags) age out the same way.
# `select` prints the ids to delete, one per line, and is what the test covers.
set -euo pipefail
cmd="${1:?select|run}"

select_ids() { # <versions.json> <protected.txt> <days> [<now>]
  local now="${4:-$(date +%s)}"
  jq -r --argjson now "$now" --argjson days "$3" --rawfile prot "$2" '
    ($prot | split("\n") | map(select(length > 0))) as $p
    | .[]
    | select((.created_at | fromdateiso8601) < ($now - $days * 86400))
    | select(.name as $n | $p | index($n) | not)
    | .id' "$1"
}

case "$cmd" in
  select) shift; select_ids "$@" ;;
  run)
    ORG="${ORG:-openctemio}" DAYS="${DAYS:-14}"
    work="$(mktemp -d)"; trap 'find "$work" -delete' EXIT
    # Digests named by an open release (a draft or pre-release): kept.
    gh api "repos/${GITHUB_REPOSITORY}/releases" --paginate --jq '.[] | select(.draft or .prerelease) | .body // ""' \
      | grep -oE 'sha256:[0-9a-f]{64}' | sort -u > "$work/protected.txt" || true
    for img in api admin-cli web console allinone; do
      pkg="ci-images%2F${img}"
      gh api "orgs/${ORG}/packages/container/${pkg}/versions" --paginate --jq '.[]' 2>"$work/err" \
        | jq -s '.' > "$work/v.json" || { echo "::notice::$img: no package yet or no access: $(head -c 200 "$work/err")"; continue; }
      for id in $(select_ids "$work/v.json" "$work/protected.txt" "$DAYS"); do
        echo "delete $img version $id"
        gh api -X DELETE "orgs/${ORG}/packages/container/${pkg}/versions/${id}" \
          || echo "::warning::could not delete $img version $id (the token needs package admin rights)"
      done
    done ;;
  *) echo "usage: $0 select|run" >&2; exit 2 ;;
esac
