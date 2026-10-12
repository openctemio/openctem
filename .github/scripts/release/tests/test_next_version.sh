#!/usr/bin/env bash
# Tests for next-version.sh and changelog.sh on a repository shaped like ours.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
NV="$RELEASE_DIR/next-version.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
scenario "$tmp"
w="$tmp/work"

# develop since v0.2.0 (squashed onto main: develop does not descend from it):
# "fix(api): after release", "chore: remove gone" -> patch. Commits that were
# released (reachable from v0.1.0 or squashed into v0.2.0) are NOT reachable
# from v0.2.0 here, which is exactly the ancestry problem: they still count.
out="$(bash "$NV" --repo "$w" --ref develop)"
assert_contains "last tag by version sort" "LAST_TAG=v0.2.0" "$out"
assert_contains "feature in the unreleased range -> minor" "NEXT_VERSION=v0.3.0" "$out"

# After a release branch records main as a parent, the range is exact.
git -C "$w" switch -q -c release/v0.3.0 develop
git -C "$w" merge -q -s ours --no-edit main
git -C "$w" switch -q main
git -C "$w" merge -q --no-ff --no-edit release/v0.3.0
git -C "$w" tag -a v0.3.0 -m v0.3.0
git -C "$w" switch -q develop
commit "$w" "fix(web): small"
commit "$w" "docs: words"
out="$(bash "$NV" --repo "$w" --ref develop)"
assert_contains "only fixes since v0.3.0 -> patch" "NEXT_VERSION=v0.3.1" "$out"
assert_contains "bump kind" "BUMP=patch" "$out"
assert_contains "commit count" "COMMITS=2" "$out"
assert_contains "fix count" "FIXES=1" "$out"

commit "$w" "feat(sensors): new thing"
assert_contains "feat -> minor" "NEXT_VERSION=v0.4.0" "$(bash "$NV" --repo "$w" --ref develop)"

git -C "$w" commit -q --allow-empty -m "refactor(api)!: drop the old endpoint"
out="$(bash "$NV" --repo "$w" --ref develop)"
assert_contains "breaking before 1.0 -> minor" "NEXT_VERSION=v0.4.0" "$out"
assert_contains "breaking counted" "BREAKING=1" "$out"
assert_contains "breaking kind" "BUMP=breaking" "$out"

# Overrides.
assert_contains "override accepted" "NEXT_VERSION=v1.0.0" "$(bash "$NV" --repo "$w" --ref develop --version v1.0.0)"
assert_rc "override not greater is refused" 2 bash "$NV" --repo "$w" --ref develop --version v0.3.0
assert_rc "override not a version is refused" 2 bash "$NV" --repo "$w" --ref develop --version 0.9

# Nothing to release.
assert_rc "no commits since the tag -> exit 3" 3 bash "$NV" --repo "$w" --ref v0.3.0

# Imported web history: an unrelated root whose old commits are reachable
# from ui/<last tag> does not count; only what came after it does.
git -C "$w" switch -q --orphan uihist
git -C "$w" rm -rq --cached . >/dev/null 2>&1 || true
commit "$w" "feat(web): imported long ago" web.txt
git -C "$w" tag ui/v0.3.0
commit "$w" "fix(web): imported after the tag" web.txt
git -C "$w" switch -q -f develop
git -C "$w" merge -q --no-ff --no-edit --allow-unrelated-histories uihist
bash "$NV" --repo "$w" --ref develop --notes "$tmp/n.md" >/dev/null
assert_not_contains "ui/<tag> history excluded" "imported long ago" "$(cat "$tmp/n.md")"
assert_contains "ui history after the tag counts" "imported after the tag" "$(cat "$tmp/n.md")"

# Hotfix: patch of the last tag, notes from the picks only.
fixsha="$(git -C "$w" log --format=%H --grep '^fix(web): small' -n 1)"
out="$(bash "$NV" --repo "$w" --mode hotfix --picks "$fixsha" --notes "$tmp/h.md")"
assert_contains "hotfix version" "NEXT_VERSION=v0.3.1" "$out"
assert_contains "hotfix kind" "BUMP=hotfix" "$out"
assert_contains "hotfix commits" "COMMITS=1" "$out"
assert_contains "hotfix notes list the pick" "fix(web): small" "$(cat "$tmp/h.md")"
assert_not_contains "hotfix notes list nothing else" "feat(sensors)" "$(cat "$tmp/h.md")"
assert_rc "hotfix without picks" 2 bash "$NV" --repo "$w" --mode hotfix
assert_rc "hotfix with a bad pick" 2 bash "$NV" --repo "$w" --mode hotfix --picks deadbeef

# Changelog preview: grouped, sanitized.
git -C "$w" commit -q --allow-empty -m "fix(security): escape @types/node in x, mail a@b.com"
bash "$NV" --repo "$w" --ref develop --notes "$tmp/notes.md" >/dev/null
notes="$(cat "$tmp/notes.md")"
assert_contains "title" "## v0.4.0" "$notes"
assert_contains "breaking group" "### Breaking changes (1)" "$notes"
assert_contains "security group" "### Security (1)" "$notes"
assert_contains "features group" "### Features (1)" "$notes"
# shellcheck disable=SC2016 # literal backticks
assert_contains "mention escaped" '`@types/node`' "$notes"
assert_not_contains "email dropped" "a@b.com" "$notes"
assert_contains "since" "since v0.3.0" "$notes"

# --max caps a group.
for i in 1 2 3; do git -C "$w" commit -q --allow-empty -m "fix: many $i"; done
notes="$(bash "$RELEASE_DIR/changelog.sh" --repo "$w" --max 2 -- develop ^v0.3.0 ^ui/v0.3.0)"
assert_contains "cap" "... and 3 more" "$notes"

finish
