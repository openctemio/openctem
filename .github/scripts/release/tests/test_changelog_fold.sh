#!/usr/bin/env bash
# Tests for the per-release changelog: server/scripts/changelog.py chooses a
# release's fragments from git (--ref / --since / --since-previous), its
# Upgrade notes block lists the "Upgrade note:" lines and the behaviour
# changes, and post-release.sh folds exactly the released fragments into
# server/CHANGELOG.md on the develop follow-up branch.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
SCRIPTS="$(cd "$RELEASE_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPTS/../.." && pwd)"
POST="$RELEASE_DIR/post-release.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

d="$tmp"
w="$d/work"
git init -q --bare -b main "$d/origin.git"
new_repo "$w"
git -C "$w" remote add origin "$d/origin.git"
mkdir -p "$w/server/scripts" "$w/server/changelog.d"
cp "$REPO_ROOT/server/scripts/changelog.py" "$w/server/scripts/changelog.py"
printf '# Changelog\n\n## Unreleased\n\nnote\n\n## v0.0.9 (2026-01-01)\n\n- old\n' >"$w/server/CHANGELOG.md"
printf '# readme\n' >"$w/server/changelog.d/README.md"
printf '### Added: first thing\n\n- one\n' >"$w/server/changelog.d/a.md"
git -C "$w" add -A && git -C "$w" commit -q -m "chore: init"
git -C "$w" tag -a v0.1.0 -m v0.1.0
git -C "$w" switch -q -c develop
cat >"$w/server/changelog.d/b.md" <<'EOF'
### Removed: the old stream

- The stream is gone.
- **Upgrade note:** unset `OLD_STREAM` before you upgrade,
  or the server refuses to start.
- Docs: none (test)
EOF
cat >"$w/server/changelog.d/c.md" <<'EOF'
### Fixed: retries

- Upgrade note: no action. Retries are skipped while a run is active.
- Docs: none (test)
EOF
cat >"$w/server/changelog.d/e.md" <<'EOF'
### Fixed: sizes

- **Upgrade notes**: a payload over 4 MiB is refused.
EOF
git -C "$w" add -A && git -C "$w" commit -q -m "feat: b c e"
# The release: main merges develop (as the release PR does) and is tagged.
git -C "$w" switch -q main
git -C "$w" merge -q --no-ff -m "chore(release): v0.2.0" develop
git -C "$w" tag -a v0.2.0 -m v0.2.0
# develop moves on after the cut.
git -C "$w" switch -q develop
printf '### Added: later\n\n- after the cut\n' >"$w/server/changelog.d/d.md"
git -C "$w" add -A && git -C "$w" commit -q -m "feat: d"
git -C "$w" push -q origin main develop --tags

cl="$w/server/scripts/changelog.py"
# --- selection --------------------------------------------------------------
notes="$(python3 "$cl" notes --ref v0.2.0 --since-previous v0.2.0)"
assert_contains "the release's fragment is in its notes" "### Removed: the old stream" "$notes"
assert_not_contains "an earlier release's fragment is not" "first thing" "$notes"
assert_not_contains "a fragment merged after the cut is not" "later" "$notes"
assert_eq "the block comes first" "### Upgrade notes" "$(sed -n 1p <<<"$notes")"
assert_contains "the upgrade note with its continuation line" \
  "- **Removed: the old stream**: unset \`OLD_STREAM\` before you upgrade, or the server refuses to start." "$notes"
assert_contains "a plain 'Upgrade note:' bullet" "- **Fixed: retries**: no action. Retries are skipped while a run is active." "$notes"
assert_contains "'Upgrade notes**:' too" "- **Fixed: sizes**: a payload over 4 MiB is refused." "$notes"
assert_eq "notes that need an action come before 'no action' ones" \
  "- **Fixed: retries**: no action. Retries are skipped while a run is active." \
  "$(sed -n '/^#### Before you upgrade/,/^#### Behaviour/p' <<<"$notes" | grep '^- ' | tail -n 1)"
assert_contains "a removal is listed as a behaviour change" "- Removed: the old stream (\`b.md\`)" "$notes"
assert_not_contains "a fix is not" "- Fixed: retries (\`c.md\`)" "$notes"
assert_eq "--since and --since-previous agree" "$notes" "$(python3 "$cl" notes --ref v0.2.0 --since v0.1.0)"
assert_contains "--since-previous latest is the newest tag" "### Added: later" "$(python3 "$cl" notes --since-previous latest)"
assert_rc "--since-previous needs a tag below it" 1 python3 "$cl" notes --since-previous v0.0.1
assert_rc "--since-previous refuses a non-version" 1 python3 "$cl" notes --since-previous main
assert_eq "nothing chosen" "No notable changes." "$(python3 "$cl" notes --ref v0.1.0 --since v0.1.0)"
assert_contains "preview takes --since too" "### Added: later" "$(python3 "$cl" preview --since v0.2.0)"
assert_not_contains "preview --since leaves the released ones out" "old stream" "$(python3 "$cl" preview --since v0.2.0)"

# --- post-release.sh folds exactly the release's fragments --------------------
out="$(bash "$POST" --repo "$w" --version v0.2.0 --mode train 2>"$tmp/err")"; rc=$?
assert_eq "post-release exits 0 ($(cat "$tmp/err"))" 0 "$rc"
assert_eq "FOLDED counts the release's fragments" 3 "$(sed -n 's/^FOLDED=//p' <<<"$out")"
assert_eq "CHANGED is only what the merge brought" "" "$(sed -n 's/^CHANGED=//p' <<<"$out")"
ph="$(sed -n 's/^HEAD=//p' <<<"$out")"
log="$(git -C "$w" show "$ph:server/CHANGELOG.md")"
date="$(git -C "$w" log -1 --format=%cs 'v0.2.0^{commit}')"
assert_contains "the section is dated with the tag" "## v0.2.0 ($date)" "$log"
assert_contains "the section has the upgrade notes" "#### Before you upgrade" "$log"
assert_contains "and the entries" "### Removed: the old stream" "$log"
assert_contains "older sections stay" "## v0.0.9 (2026-01-01)" "$log"
assert_not_contains "a later fragment is not folded" "after the cut" "$log"
files="$(git -C "$w" ls-tree --name-only "$ph" server/changelog.d/ | xargs -n1 basename | paste -sd' ' -)"
assert_eq "folded fragments are deleted, the rest stay" "README.md a.md d.md" "$files"
assert_eq "the fold is its own commit on top of the merge" "chore(changelog): fold the v0.2.0 fragments into server/CHANGELOG.md" \
  "$(git -C "$w" log -1 --format=%s "$ph")"
assert_eq "the merge stays a merge commit" 3 "$(git -C "$w" rev-list --parents -n 1 "${ph}^" | wc -w)"

# --- release refuses a second section and a bad date ---------------------------
git -C "$w" switch -q --detach "$ph"
assert_rc "a version already folded is refused" 1 python3 "$cl" release v0.2.0
assert_rc "a malformed --date is refused" 2 python3 "$cl" release v0.3.0 --date 12/11/2026

finish
