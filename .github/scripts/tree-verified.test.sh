#!/usr/bin/env bash
# Tests for tree-verified.sh. Run: bash .github/scripts/tree-verified.test.sh
# A scratch git repository and a fake `gh` on PATH; nothing reaches GitHub.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/tree-verified.sh"
pass=0 failed=0
d="$(mktemp -d)"
fix="$d/fix"; mkdir -p "$fix" "$d/bin" "$d/repo"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid

# The fake `gh api <endpoint> [--paginate] --jq <filter>`: the endpoint's query
# string is dropped, "/" becomes "_", and the fixture file of that name is
# filtered with the caller's jq filter. A missing fixture is an API error.
cat >"$d/bin/gh" <<'GH'
#!/usr/bin/env bash
[ -n "${FAKE_FAIL:-}" ] && exit 1
ep="" filter="."
shift
while [ $# -gt 0 ]; do
  case "$1" in
    --paginate) ;;
    --jq) shift; filter="$1" ;;
    *) ep="$1" ;;
  esac
  shift
done
f="$FIX/$(echo "${ep%%\?*}" | tr / _)"
[ -f "$f" ] || exit 1
jq -r "$filter" "$f"
GH
chmod +x "$d/bin/gh"

git -C "$d/repo" init -q -b main
echo a >"$d/repo/f"; git -C "$d/repo" add f; git -C "$d/repo" commit -qm base
base=$(git -C "$d/repo" rev-parse HEAD)
echo b >"$d/repo/f"; git -C "$d/repo" commit -qam same-as-queue
dev=$(git -C "$d/repo" rev-parse HEAD)               # a develop commit
git -C "$d/repo" update-ref refs/remotes/origin/develop "$dev"
git -C "$d/repo" update-ref refs/remotes/origin/main "$base"
git -C "$d/repo" commit -q --amend -m "queue commit, same tree as develop's"   # new sha, same tree
q=$(git -C "$d/repo" rev-parse HEAD)
echo c >"$d/repo/f"; git -C "$d/repo" commit -qam other-tree
other=$(git -C "$d/repo" rev-parse HEAD)
tree=$(git -C "$d/repo" rev-parse "$q^{tree}")
otree=$(git -C "$d/repo" rev-parse "$other^{tree}")
pr=1111111111111111111111111111111111111111
ref="refs/heads/gh-readonly-queue/develop/pr-77-$q"
names="API CI OK,Web CI OK,CodeQL OK,E2E OK,All-in-one OK,Secret Scanning,Workflow Lint"

# set_runs <commit> <conclusion of "E2E OK"> <app of "E2E OK"> <tree recorded> [extra check-run json]
set_runs() {
  local c=$1 e2e=$2 app=$3 rec=$4 n id=100 arr="${5:-}"
  IFS=, read -ra ns <<<"$names"
  for n in "${ns[@]}"; do
    id=$((id + 1))
    local concl=success a=github-actions ann=0
    if [ "$n" = "E2E OK" ]; then concl=$e2e; a=$app; fi
    if [ "$n" = "API CI OK" ]; then ann=1; fi
    arr+="{\"id\":$id,\"name\":\"$n\",\"status\":\"completed\",\"conclusion\":\"$concl\",\"html_url\":\"https://x/$id\",\"app\":{\"slug\":\"$a\"},\"output\":{\"annotations_count\":$ann}},"
  done
  echo "{\"check_runs\":[${arr%,}]}" >"$fix/repos_o_r_commits_${c}_check-runs"
  echo "[{\"message\":\"openctem-tested-tree $rec\"},{\"message\":\"unrelated\"}]" >"$fix/repos_o_r_check-runs_101_annotations"
}
echo "{\"head\":{\"sha\":\"$pr\"}}" >"$fix/repos_o_r_pulls_77"

run() { # <expect> <name> [env...]
  local want=$1 name=$2 got; shift 2
  got="$(cd "$d/repo" && env PATH="$d/bin:$PATH" FIX="$fix" EVENT=merge_group SHA=$q HEAD_REF=$ref REPO=o/r \
    GITHUB_OUTPUT= "$@" bash "$script" 2>/dev/null | sed -n "s/^verified=//p")"
  if [ "$got" = "$want" ]; then echo "ok:   $name"; pass=$((pass + 1)); else echo "FAIL: $name (want $want, got $got)"; failed=$((failed + 1)); fi
}
clear() { find "$fix" -mindepth 1 -delete; echo "{\"head\":{\"sha\":\"$pr\"}}" >"$fix/repos_o_r_pulls_77"; }

set_runs $pr success github-actions "$tree"
run true "PR head passed on a merge ref with our tree"
clear; set_runs $pr success github-actions "$otree"
run false "the PR was tested on a different tree"
clear; set_runs $pr failure github-actions "$tree"
run false "a required check failed on the candidate"
clear; set_runs $pr skipped github-actions "$tree"
run true "a skipped required check counts as passed"
clear; set_runs $pr success some-other-app "$tree"
run false "E2E OK posted only by another integration does not count"
clear; set_runs $pr success github-actions "$tree" '{"id":900,"name":"E2E OK","status":"completed","conclusion":"failure","html_url":"https://x/900","app":{"slug":"some-other-app"},"output":{"annotations_count":0}},'
run true "a failing run of another integration is ignored"
clear; set_runs $pr success github-actions "$tree" '{"id":901,"name":"E2E OK","status":"in_progress","conclusion":null,"html_url":"https://x/901","app":{"slug":"github-actions"},"output":{"annotations_count":0}},'
run false "a latest run still in progress"
clear; set_runs $pr success github-actions "$tree"
echo '[{"message":"unrelated"}]' >"$fix/repos_o_r_check-runs_101_annotations"
run false "no tested-tree record"
clear; set_runs $pr success github-actions "$tree"
run false "not a merge_group event" EVENT=pull_request
run false "push is not in TREE_EVENTS" EVENT=push TREE_EVENTS=merge_group
run false "api error runs everything" FAKE_FAIL=1
run false "malformed sha" SHA='abc;rm'
run false "queue ref that does not parse" HEAD_REF=refs/heads/gh-readonly-queue/develop/pr-x-$q

# A group whose tree differs from the PR's tested tree never matches.
clear; set_runs $pr success github-actions "$tree"
run false "the group tree differs from the PR's tree" SHA=$other

# An earlier commit of develop with the same tree and passing checks.
clear; set_runs $dev success github-actions "$tree"
run true "an earlier develop commit with the same tree passed"
clear; set_runs $dev failure github-actions "$tree"
run false "the earlier develop commit failed a check"
clear; set_runs $dev success github-actions "$tree"
run false "develop commit with the same tree but the queue ref names no known PR head" HEAD_REF=refs/heads/gh-readonly-queue/develop/pr-77-$q TREE_WINDOW=0

# The record is printed on every event.
rec="$(cd "$d/repo" && env PATH="$d/bin:$PATH" FIX="$fix" EVENT=pull_request SHA=$q REPO=o/r bash "$script" 2>/dev/null | grep -c "^::notice title=tested-tree::openctem-tested-tree $tree\$" || true)"
if [ "$rec" = 1 ]; then echo "ok:   the tested tree is recorded"; pass=$((pass + 1)); else echo "FAIL: record"; failed=$((failed + 1)); fi

# Note text and GITHUB_OUTPUT.
clear; set_runs $pr success github-actions "$tree"
note="$(cd "$d/repo" && env PATH="$d/bin:$PATH" FIX="$fix" EVENT=merge_group SHA=$q HEAD_REF=$ref REPO=o/r GITHUB_OUTPUT="$d/gho" bash "$script" 2>/dev/null | sed -n 's/^note=//p')"
want="tree $tree already verified at $pr (https://x/101)"
if [ "$note" = "$want" ] && grep -qx "verified=true" "$d/gho"; then echo "ok:   note and outputs"; pass=$((pass + 1)); else echo "FAIL: note (got $note)"; failed=$((failed + 1)); fi

find "$d" -mindepth 1 -delete; rmdir "$d"
echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
