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
dev="$(git -C "$w" rev-parse develop)"

# --- train -------------------------------------------------------------------
out="$(bash "$CUT" --repo "$w" --version v0.3.0 --sha "$dev" --push 2>"$tmp/err")"; rc=$?
assert_eq "train: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
assert_contains "train: branch" "BRANCH=release/v0.3.0" "$out"
assert_contains "train: deliberate deletion noted" "gone.txt is on main, deleted on develop" "$(cat "$tmp/err")"
head="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_eq "train: head is the -s ours merge (two parents)" 3 "$(git -C "$w" rev-list --parents -n 1 "$head" | wc -w)"
assert_eq "train: version commit sits on develop's commit" "$dev" "$(git -C "$w" rev-parse "$head^1^1")"
assert_eq "train: tree is develop's plus the version commit" \
  "$(printf 'api/deploy/.env.example\napi/deploy/docker-compose.job-signer.yml\napi/deploy/docker-compose.yml\napi/internal/versions/versions.yaml\nversions.yaml')" \
  "$(git -C "$w" diff --name-only "$dev" "$head")"
assert_contains "train: versions.yaml names the release" "release: v0.3.0" "$(git -C "$w" show "$head:versions.yaml")"
assert_contains "train: the checkout defaults to the release" "OPENCTEM_VERSION=v0.3.0" "$(git -C "$w" show "$head:api/deploy/.env.example")"
assert_contains "train: compose defaults to the release" "OPENCTEM_VERSION:-v0.3.0}" "$(git -C "$w" show "$head:api/deploy/docker-compose.yml")"
assert_rc "train: main is an ancestor" 0 git -C "$w" merge-base --is-ancestor origin/main "$head"
assert_eq "train: pushed" "$head" "$(git -C "$w" ls-remote origin refs/heads/release/v0.3.0 | cut -f1)"
# The PR merges into main without conflicts and yields the release branch's tree.
merged_tree="$(git -C "$w" merge-tree --write-tree origin/main "$head")"
assert_eq "train: merges into main cleanly to the branch's tree" "$(git -C "$w" rev-parse "$head^{tree}")" "$merged_tree"

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
out="$(bash "$CUT" --repo "$w" --version v0.2.1 --mode hotfix --picks "$fix" --push 2>"$tmp/err")"; rc=$?
assert_eq "hotfix: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
head="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_eq "hotfix: built on the tag" "$(git -C "$w" rev-parse 'v0.2.0^{commit}')" "$(git -C "$w" rev-parse "$head~2")"
assert_contains "hotfix: cherry-picked with -x" "cherry picked from commit $fix" "$(git -C "$w" log -1 --format=%B "$head~1")"
assert_eq "hotfix: head has one parent" 2 "$(git -C "$w" rev-list --parents -n 1 "$head" | wc -w)"
assert_contains "hotfix: versions.yaml names the hotfix" "release: v0.2.1" "$(git -C "$w" show "$head:versions.yaml")"
assert_contains "hotfix: the checkout defaults to the hotfix" "OPENCTEM_VERSION=v0.2.1" "$(git -C "$w" show "$head:api/deploy/.env.example")"
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

finish
