#!/usr/bin/env bash
# Tests for publish-release.sh with a stub gh: the release body stays under
# GitHub's 125,000-character limit however long the generated notes are.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
PUB="$RELEASE_DIR/publish-release.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
# Stub gh: no release yet; generate-notes prints $NOTES_LINES lines; create
# copies its --notes-file to $tmp/body.
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "release view") exit 1 ;;
  "api repos/"*) for i in $(seq 1 "$NOTES_LINES"); do echo "* change number $i by someone in https://github.com/o/r/pull/$i"; done ;;
  "release create")
    echo "$*" >"$ARGS"
    while [ $# -gt 0 ]; do [ "$1" = --notes-file ] && cp "$2" "$BODY"; shift; done ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$tmp/bin/gh"
# Stub git: ls-remote lists the tags in $TAGS (no network); everything else is real git.
REAL_GIT="$(command -v git)"
export REAL_GIT
cat >"$tmp/bin/git" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = ls-remote ]; then
  for t in $TAGS; do printf '0000000000000000000000000000000000000000\trefs/tags/%s\n' "$t"; done
  exit 0
fi
exec "$REAL_GIT" "$@"
STUB
chmod +x "$tmp/bin/git"
echo "Header line" >"$tmp/header.md"
export PATH="$tmp/bin:$PATH" GITHUB_REPOSITORY=o/r BODY="$tmp/body" ARGS="$tmp/args" TAGS="v0.9.0 v1.0.0" GH_RETRY_ATTEMPTS=1

NOTES_LINES=10 bash "$PUB" v1.0.0 "$tmp/header.md"; rc=$?
assert_eq "short notes: exit 0" 0 "$rc"
assert_contains "short notes: header kept" "Header line" "$(cat "$tmp/body")"
assert_contains "short notes: all generated lines" "change number 10 " "$(cat "$tmp/body")"

NOTES_LINES=3000 bash "$PUB" v1.0.0 "$tmp/header.md"; rc=$?
assert_eq "long notes: exit 0" 0 "$rc"
size="$(wc -c <"$tmp/body")"
assert_rc "long notes: body under 125000 ($size)" 0 test "$size" -lt 125000
assert_contains "long notes: cut is said" "The list is cut here" "$(cat "$tmp/body")"
assert_contains "long notes: header kept" "Header line" "$(head -1 "$tmp/body")"


# Only the newest release line is "Latest": a hotfix of an older line is not.
NOTES_LINES=1 TAGS="v1.0.0 v1.1.0" bash "$PUB" v1.0.0 "$tmp/header.md"; rc=$?
assert_eq "older line: exit 0" 0 "$rc"
assert_contains "older line: not latest" "--latest=false" "$(cat "$tmp/args")"
NOTES_LINES=1 TAGS="v1.0.0 v1.1.0" bash "$PUB" v1.1.0 "$tmp/header.md"; rc=$?
assert_eq "newest line: exit 0" 0 "$rc"
assert_contains "newest line: latest" "--latest=true" "$(cat "$tmp/args")"
NOTES_LINES=1 TAGS="" bash "$PUB" v1.0.0 "$tmp/header.md" 2>/dev/null; rc=$?
assert_eq "no tags listed: refuses" 1 "$rc"
finish
