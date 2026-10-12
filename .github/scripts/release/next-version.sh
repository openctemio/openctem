#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# next-version.sh: propose the next release version from the conventional
# commits since the last tag (api/docs/rfcs/RFC-037 §3.6).
#
#   next-version.sh [--ref REV] [--version vX.Y.Z] [--notes FILE] [--repo DIR]
#   next-version.sh --mode hotfix --picks "SHA ..." [--notes FILE] [--repo DIR]
#
#   --ref      the commit to release (default HEAD)
#   --version  an override: must be vX.Y.Z and greater than the last tag
#   --mode     train (default) or hotfix: the last tag's patch + 1, made of
#              the commits in --picks (cherry-picked onto the last tag)
#   --notes    write a Markdown changelog preview of the commits to FILE
#
# Prints KEY=VALUE lines (append them to $GITHUB_OUTPUT):
#   LAST_TAG  NEXT_VERSION  BUMP (breaking|feat|patch|override|hotfix)
#   COMMITS  BREAKING  FEATURES  FIXES
# Exit 3: nothing to release (no commits since the last tag).
# Exit 2: bad input (an override that is not greater than the last tag, ...).
#
# Commits counted: reachable from --ref, not from the last tag, and not from
# ui/<last tag> (the imported history of openctemio/ui, once), merges excluded.
# Tags are compared by version sort, never with `git describe`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

REPO="."
REF="HEAD"
OVERRIDE=""
MODE="train"
PICKS=""
NOTES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="$2"; shift ;;
    --version) OVERRIDE="$2"; shift ;;
    --mode) MODE="$2"; shift ;;
    --picks) PICKS="$2"; shift ;;
    --notes) NOTES="$2"; shift ;;
    --repo) REPO="$2"; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); if ($0 !~ /^shellcheck/) print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$MODE" == train || "$MODE" == hotfix ]] || { echo "--mode must be train or hotfix" >&2; exit 2; }
if [[ "$MODE" == hotfix ]]; then
  [[ -n "${PICKS// /}" ]] || { echo "--mode hotfix needs --picks" >&2; exit 2; }
  for p in $PICKS; do
    git -C "$REPO" rev-parse -q --verify "$p^{commit}" >/dev/null || { echo "not a commit: $p" >&2; exit 2; }
  done
fi

last="$(rel_latest_tag "$REPO")"
range=("$REF")
if [[ "$MODE" == hotfix ]]; then
  # Exactly the picked commits.
  read -r -a range <<<"--no-walk $PICKS"
  [[ -n "$last" ]] || { echo "a hotfix needs a previous release tag" >&2; exit 2; }
elif [[ -n "$last" ]]; then
  range+=("^$last")
  if git -C "$REPO" rev-parse -q --verify "refs/tags/ui/$last" >/dev/null; then
    range+=("^refs/tags/ui/$last")
  fi
else
  last="v0.0.0"
fi

commits="$(git -C "$REPO" rev-list --count --no-merges "${range[@]}")"
kind="$(git -C "$REPO" log --no-merges --format='%B%x1e' "${range[@]}" | rel_bump_kind)"

subjects() { git -C "$REPO" log --no-merges --format='%s' "${range[@]}"; }
count() { subjects | grep -cE "$1" || true; }
breaking="$(git -C "$REPO" log --no-merges --format='%B%x1e' "${range[@]}" |
  awk -v RS='\036' '{ sub(/^\n+/, ""); if ($0 == "") next; split($0, l, "\n");
    b = (l[1] ~ /^[A-Za-z]+(\([^)]*\))?!:/); for (i in l) if (l[i] ~ /^BREAKING[ -]CHANGE:/) b = 1; n += b }
    END { print n + 0 }')"
features="$(count '^feat(\([^)]*\))?!?:')"
fixes="$(count '^fix(\([^)]*\))?!?:')"

if [[ -n "$OVERRIDE" ]]; then
  rel_is_version "$OVERRIDE" || { echo "override '$OVERRIDE' is not vX.Y.Z" >&2; exit 2; }
  if [[ "$last" != v0.0.0 ]] && ! rel_version_gt "$OVERRIDE" "$last"; then
    echo "override $OVERRIDE is not greater than the last tag $last" >&2
    exit 2
  fi
  next="$OVERRIDE"
  bump="override"
elif [[ "$MODE" == hotfix ]]; then
  next="$(rel_next_version "$last" patch)"
  bump="hotfix"
else
  if ! next="$(rel_next_version "$last" "$kind")"; then
    echo "nothing to release: no commits since $last" >&2
    echo "LAST_TAG=$last"
    exit 3
  fi
  bump="$kind"
fi

if [[ -n "$NOTES" ]]; then
  "$HERE/changelog.sh" --repo "$REPO" --title "$next" --since "$last" -- "${range[@]}" >"$NOTES"
fi

cat <<EOF
LAST_TAG=$last
NEXT_VERSION=$next
BUMP=$bump
COMMITS=$commits
BREAKING=$breaking
FEATURES=$features
FIXES=$fixes
EOF
