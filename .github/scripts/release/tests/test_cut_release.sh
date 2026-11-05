#!/usr/bin/env bash
# Tests for cut-release.sh: train and hotfix branches against a local origin.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
CUT="$RELEASE_DIR/cut-release.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
scenario "$tmp"
w="$tmp/work"

stub_release_lists "$tmp/stub"
dev="$(git -C "$w" rev-parse develop)"

# --- train -------------------------------------------------------------------
out="$(bash "$CUT" --repo "$w" --version v0.3.0 --sha "$dev" --push 2>"$tmp/err")"; rc=$?
assert_eq "train: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
assert_contains "train: branch" "BRANCH=release/v0.3.0" "$out"
assert_contains "train: deliberate deletion noted" "gone.txt is on main, deleted on develop" "$(cat "$tmp/err")"
head="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_eq "train: head is the -s ours merge (two parents)" 3 "$(git -C "$w" rev-list --parents -n 1 "$head" | wc -w)"
assert_eq "train: version commit sits on develop's commit" "$dev" "$(git -C "$w" rev-parse "$head^1^1")"
assert_eq "train: tree is develop's plus api/deploy/VERSION only" "api/deploy/VERSION" "$(git -C "$w" diff --name-only "$dev" "$head")"
assert_eq "train: the checkout installs the release" "v0.3.0" "$(git -C "$w" show "$head:api/deploy/VERSION")"
assert_eq "train: versions.yaml is untouched" "$(git -C "$w" show "$dev:versions.yaml")" "$(git -C "$w" show "$head:versions.yaml")"
assert_rc "train: main is an ancestor" 0 git -C "$w" merge-base --is-ancestor origin/main "$head"
assert_eq "train: pushed" "$head" "$(git -C "$w" ls-remote origin refs/heads/release/v0.3.0 | cut -f1)"
# The PR merges into main without conflicts and yields the release branch's tree.
merged_tree="$(git -C "$w" merge-tree --write-tree origin/main "$head")"
assert_eq "train: merges into main cleanly to the branch's tree" "$(git -C "$w" rev-parse "$head^{tree}")" "$merged_tree"

# The version commit refreshes each component's built-in latest from its
# published releases and copies it to the consumers; min is never touched, a
# component with an unpublished image keeps the previous release, and an
# older published release never lowers a latest.
digest="sha256:$(printf 'c%.0s' {1..64})"
echo '[{"tagName":"v0.7.0","publishedAt":"2026-11-01T00:00:00Z"},{"tagName":"v0.6.9","publishedAt":"2026-10-30T00:00:00Z"}]' >"$tmp/stub/releases/sensor.json"
echo "$digest" >"$tmp/stub/images/ghcr.io_openctemio_sensor_v0.6.9"
echo '[{"tagName":"v0.4.0","publishedAt":"2026-11-05T00:00:00Z"}]' >"$tmp/stub/releases/ci.json"
echo "$digest" >"$tmp/stub/images/ghcr.io_openctemio_ci_v0.4.0"
echo '[{"tagName":"v0.1.0","publishedAt":"2026-11-05T00:00:00Z"}]' >"$tmp/stub/releases/sdk-go.json"
out="$(bash "$CUT" --repo "$w" --version v0.6.0 --sha "$dev" 2>"$tmp/err")"; rc=$?
assert_eq "refresh: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
rhead="$(sed -n 's/^HEAD=//p' <<<"$out")"
manifest="$(git -C "$w" show "$rhead:versions.yaml")"
assert_contains "refresh: sensor.latest = newest release with an image" "latest: v0.6.9" "$manifest"
assert_contains "refresh: ci.latest raised" "$(printf 'ci:\n  latest: v0.4.0')" "$manifest"
assert_contains "refresh: an older sdk release never lowers it" "$(printf 'sdk:\n  latest: v0.14.0')" "$manifest"
assert_eq "refresh: min untouched" "$(git -C "$w" show "$dev:versions.yaml" | grep -c 'min:')" "$(grep -c 'min: ""' <<<"$manifest")"
assert_eq "refresh: embedded copy follows" "$manifest" "$(git -C "$w" show "$rhead:api/internal/versions/versions.yaml")"
assert_contains "refresh: console fallback follows" "CI_RELEASE_FALLBACK = 'v0.4.0'" "$(git -C "$w" show "$rhead:web/src/features/ci-runners/lib/ci.ts")"
assert_contains "refresh: bundled sensor default follows" "SENSOR_VERSION:-v0.6.9" "$(git -C "$w" show "$rhead:api/deploy/docker-compose.sensor.yml")"
assert_contains "refresh: unreadable component only warns" "connector-tenable.latest stays v0.1.0" "$(cat "$tmp/err")"
git -C "$w" branch -q -D release/v0.6.0
out="$(bash "$CUT" --repo "$w" --version v0.6.0 --sha "$dev" --no-refresh-latest 2>"$tmp/err")"; rc=$?
assert_eq "no refresh: exit 0" 0 "$rc"
assert_eq "no refresh: versions.yaml untouched" "$(git -C "$w" show "$dev:versions.yaml")" "$(git -C "$w" show "$(sed -n 's/^HEAD=//p' <<<"$out"):versions.yaml")"
git -C "$w" branch -q -D release/v0.6.0
find "$tmp/stub/releases" "$tmp/stub/images" -type f -delete

assert_rc "train: branch exists -> refused" 1 bash "$CUT" --repo "$w" --version v0.3.0 --sha "$dev"
assert_rc "train: not greater than the last tag -> refused" 1 bash "$CUT" --repo "$w" --version v0.2.0 --sha "$dev"
assert_rc "train: bad version" 2 bash "$CUT" --repo "$w" --version 0.3.0 --sha "$dev"
assert_rc "train: needs --sha" 2 bash "$CUT" --repo "$w" --version v0.3.1

# A file only main ever had (a hotfix made on main) blocks the cut.
git -C "$w" switch -q main
commit "$w" "fix: made on main only" onlymain.txt
git -C "$w" push -q origin main
out="$(bash "$CUT" --repo "$w" --version v0.4.0 --sha "$dev" 2>&1)"; rc=$?
assert_eq "file only on main: refused" 1 "$rc"
assert_contains "file only on main: named" "onlymain.txt" "$out"
git -C "$w" reset -q --hard HEAD~1
git -C "$w" push -q -f origin main
git -C "$w" switch -q develop

# A file develop deleted while resolving a merge (the deletion lives only in
# the merge commit) is a deliberate removal, not a main-only fix.
main0="$(git -C "$w" rev-parse main)"
commit "$w" "chore: add gone2" gone2.txt
git -C "$w" switch -q main
git -C "$w" checkout -q develop -- gone2.txt
git -C "$w" commit -q -m "chore: carry gone2"
git -C "$w" push -q origin main
git -C "$w" switch -q -c side develop
commit "$w" "feat: side work" side.txt
git -C "$w" switch -q develop
git -C "$w" merge -q --no-ff --no-commit side
git -C "$w" rm -q gone2.txt
git -C "$w" commit -q -m "Merge side; drop gone2"
dev2="$(git -C "$w" rev-parse develop)"
out="$(bash "$CUT" --repo "$w" --version v0.5.0 --sha "$dev2" 2>&1)"; rc=$?
assert_eq "deleted in a merge: accepted ($out)" 0 "$rc"
assert_contains "deleted in a merge: noted" "gone2.txt is on main, deleted on develop" "$out"
git -C "$w" branch -q -D release/v0.5.0
git -C "$w" reset -q --hard "$dev"
git -C "$w" switch -q main
git -C "$w" reset -q --hard "$main0"
git -C "$w" push -q -f origin main
git -C "$w" switch -q develop

# --- hotfix --------------------------------------------------------------------
fix="$(git -C "$w" log --format=%H --grep '^fix(api): after release' -n 1 develop)"
echo '[{"tagName":"v0.7.0","publishedAt":"2026-11-01T00:00:00Z"}]' >"$tmp/stub/releases/sensor.json"
echo "sha256:$(printf 'e%.0s' {1..64})" >"$tmp/stub/images/ghcr.io_openctemio_sensor_v0.7.0"
out="$(bash "$CUT" --repo "$w" --version v0.2.1 --mode hotfix --picks "$fix" --push 2>"$tmp/err")"; rc=$?
find "$tmp/stub/releases" "$tmp/stub/images" -type f -delete
assert_eq "hotfix: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
head="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_eq "hotfix: built on the tag" "$(git -C "$w" rev-parse 'v0.2.0^{commit}')" "$(git -C "$w" rev-parse "$head~2")"
assert_contains "hotfix: cherry-picked with -x" "cherry picked from commit $fix" "$(git -C "$w" log -1 --format=%B "$head~1")"
assert_eq "hotfix: head has one parent" 2 "$(git -C "$w" rev-list --parents -n 1 "$head" | wc -w)"
assert_eq "hotfix: the checkout installs the hotfix" "v0.2.1" "$(git -C "$w" show "$head:api/deploy/VERSION")"
assert_eq "hotfix: no latest refresh (only VERSION and the pick change)" "api/deploy/VERSION d.txt" "$(git -C "$w" diff --name-only "v0.2.0" "$head" | tr '\n' ' ' | sed 's/ $//')"
assert_rc "hotfix: still has gone.txt (no develop changes leak in)" 0 git -C "$w" cat-file -e "$head:gone.txt"
assert_rc "hotfix: wrong version refused" 1 bash "$CUT" --repo "$w" --version v0.3.0 --mode hotfix --picks "$fix"
assert_rc "hotfix: needs picks" 2 bash "$CUT" --repo "$w" --version v0.2.2 --mode hotfix
# A pick that does not apply is refused and leaves no branch behind.
git -C "$w" switch -q -c conflict develop
echo "conflict" >"$w/a.txt"; git -C "$w" commit -qam "fix: rewrite a"
echo "conflict2" >"$w/a.txt"; git -C "$w" commit -qam "fix: rewrite a again"
bad="$(git -C "$w" rev-parse HEAD)"
git -C "$w" switch -q develop
git -C "$w" push -q origin :refs/heads/release/v0.2.1
git -C "$w" branch -q -D release/v0.2.1
out="$(bash "$CUT" --repo "$w" --version v0.2.1 --mode hotfix --picks "$bad" 2>&1)"; rc=$?
assert_eq "hotfix conflict: refused" 1 "$rc"
assert_contains "hotfix conflict: explained" "conflicts" "$out"
assert_rc "hotfix conflict: no branch left behind" 1 git -C "$w" rev-parse -q --verify refs/heads/release/v0.2.1

# A PR's merge commit (the queue merges with MERGE commits) is picked by its
# first-parent diff (-m 1) instead of failing with "is a merge but no -m".
git -C "$w" switch -q -c prside develop~1
commit "$w" "fix(api): pr work" pr.txt
git -C "$w" switch -q -c prmerge develop~1
git -C "$w" merge -q --no-ff -m "Merge pull request #7 from side" prside
mergec="$(git -C "$w" rev-parse HEAD)"
git -C "$w" switch -q develop
out="$(bash "$CUT" --repo "$w" --version v0.2.1 --mode hotfix --picks "$mergec" 2>&1)"; rc=$?
assert_eq "hotfix merge-commit pick: exit 0 ($out)" 0 "$rc"
assert_rc "hotfix merge-commit pick: the PR's file arrived" 0 git -C "$w" cat-file -e "release/v0.2.1:pr.txt"
git -C "$w" branch -q -D release/v0.2.1

# The version checks run with the scripts of the tag's own tree: a tag whose
# layout the current scripts do not know must not be judged by them.
git -C "$w" switch -q main
mkdir -p "$w/.github/scripts/release"
cat >"$w/.github/scripts/release/sync-versions.sh" <<'STUB'
#!/usr/bin/env bash
echo "TAG-OWN-CHECKER $*" >&2
exit 0
STUB
git -C "$w" add .github/scripts/release/sync-versions.sh
git -C "$w" commit -q -m "ci: tag-owned checker"
git -C "$w" tag -f -a v0.2.0 -m v0.2.0 >/dev/null
git -C "$w" push -q -f origin main v0.2.0
git -C "$w" switch -q develop
out="$(bash "$CUT" --repo "$w" --version v0.2.1 --mode hotfix --picks "$fix" 2>&1)"; rc=$?
assert_eq "hotfix: exit 0 with the tag's checker ($out)" 0 "$rc"
assert_contains "hotfix: the tag's own sync-versions.sh ran" "TAG-OWN-CHECKER" "$out"

finish
