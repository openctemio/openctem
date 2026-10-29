#!/usr/bin/env bash
# Self-test: the pre-push hook of a linked git worktree lints only what the
# branch adds. git hands a worktree hook an absolute GIT_DIR; if it stays set,
# the `git diff <base>` that golangci-lint --new-from-rev runs inside api/ sees
# api/ as the work tree and reports the whole tree as new.
set -euo pipefail
src=$(cd "$(dirname "$0")/../.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git() { command git -c user.name=t -c user.email=t@example.com "$@"; }

git init -q --bare "$t/origin.git"
git init -q -b develop "$t/main"
mkdir -p "$t/main/api/pkg" "$t/main/scripts" "$t/main/.githooks"
printf 'package pkg\n' > "$t/main/api/pkg/old.go"
printf 'package pkg\n' > "$t/main/api/pkg/old2.go"
cp "$src/scripts/precheck.sh" "$t/main/scripts/"
cp "$src/.githooks/pre-push" "$t/main/.githooks/"
git -C "$t/main" add -A
git -C "$t/main" commit -q -m base
git -C "$t/main" remote add origin "$t/origin.git"
git -C "$t/main" push -q origin develop
git -C "$t/main" fetch -q origin
git -C "$t/main" worktree add -q "$t/wt" -b feature origin/develop
printf 'package pkg\n' > "$t/wt/api/pkg/new.go"
git -C "$t/wt" add api/pkg/new.go
git -C "$t/wt" commit -q -m change

# make stub: records the files `git diff <BASE_REF>` reports from api/
mkdir -p "$t/bin"
cat > "$t/bin/make" <<'S'
#!/usr/bin/env bash
dir=; base=
while [ $# -gt 0 ]; do
  case $1 in -C) dir=$2; shift ;; BASE_REF=*) base=${1#BASE_REF=} ;; esac
  shift
done
cd "$dir"
git diff --name-only "$base" > "$MAKE_OUT"
S
chmod +x "$t/bin/make"

# Run the hook the way git does in a linked worktree.
cd "$t/wt"
export MAKE_OUT="$t/diff.txt" BASE=origin/develop
GIT_DIR=$(command git rev-parse --absolute-git-dir) PATH="$t/bin:$PATH" sh .githooks/pre-push >/dev/null
got=$(cat "$t/diff.txt")
if [ "$got" != "api/pkg/new.go" ]; then
  echo "FAIL: lint base diff from api/ was: [$got], want only api/pkg/new.go"
  exit 1
fi
echo "ok: worktree pre-push lints only the branch's own changes"
