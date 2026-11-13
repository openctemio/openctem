#!/usr/bin/env bash
# Inventory guard for the backend directory name (research/414, the api/ ->
# server/ rename). Fails when a tracked file still names the OLD module path
# github.com/openctemio/openctem/api or the OLD directory api/ as a repository
# path, so a branch that was not caught up (scripts/rename/catch-up.sh) or a new
# file written from habit cannot bring the old name back.
#
# What is NOT a hit (the allow-list):
#   - URL paths: /api/v1/..., /api/health, https://api.example.com (an "api/"
#     preceded by "/", ".", a word character or "-" is never a repository path);
#   - runtime paths such as /opt/openctem/api/ and the kit layout $d/api/openapi
#     (preceded by "/");
#   - image names (openctem-api), compose service names, log values (service=api);
#   - released history: every CHANGELOG.md and .git-blame-ignore-revs;
#   - the rename tooling itself (scripts/rename/), this guard and its test;
#   - merged migrations (**/migrations/**/*.sql): a merged migration never
#     changes, so its comments keep naming the layout it was written in;
#   - a relative path that resolves next to the file that names it
#     (server/docs/README.md linking api/README.md = server/docs/api/README.md);
#   - a line that carries the marker "rename-guard: allow" (for a deliberate
#     reference to the old layout, e.g. reading an old release tag).
#
# Usage: check-backend-dir-name.sh [repo-root]   (default: the repository root)
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$root"

OLD=api
NEW=server
# Repository-root names inside the backend directory. Keep in sync with TOP in
# scripts/rename/backend-dir.sh.
TOP='api/openapi|internal|pkg|cmd|configs|deploy|docs|ee|examples|migrations|proto|scripts|tests|tools|changelog\.d|go\.mod|go\.sum|Makefile|Dockerfile|docker-compose|CHANGELOG|CLAUDE|README|LICENSE|trivy\.yaml|\.air\.toml|\.golangci|\.dockerignore|\.gitignore|\.gitleaksignore|\.betterleaks|\.pre-commit-config|\.gitattributes|\.env|\*|\.\.\.'
WORD='[:alnum:]_./~{}$-'

excludes=(
  ':(exclude,glob)**/CHANGELOG.md'
  ':(exclude).git-blame-ignore-revs'
  ':(exclude,glob)scripts/rename/**'
  ':(exclude).github/scripts/check-backend-dir-name.sh'
  ':(exclude).github/scripts/check-backend-dir-name.test.sh'
  ':(exclude,glob)**/node_modules/**'
  ':(exclude,glob)**/package-lock.json'
  ':(exclude,glob)**/migrations/**/*.sql'
)

fail=0
# Drops hits whose every old-directory path resolves next to the file (a
# relative link into a sibling folder named like the old directory).
relative_ok() {
  python3 -c '
import os, re, sys
pat = re.compile(r"(?<![\w./~{}$-])api/[^\s)`\"\x27#,;:]+")
for line in sys.stdin:
    f, _, rest = line.partition(":")
    _, _, text = rest.partition(":")
    hits = pat.findall(text)
    if hits and all(os.path.exists(os.path.join(os.path.dirname(f), h)) for h in hits):
        continue
    sys.stdout.write(line)
'
}
report() { # <title> <pattern>
  local out
  out="$(git grep -nIP -e "$2" -- . "${excludes[@]}" 2>/dev/null | grep -vF 'rename-guard: allow' | relative_ok || true)"
  if [[ -n "$out" ]]; then
    echo "::error::$1"
    printf '%s\n' "$out" | head -n 40
    fail=1
  fi
}

report "the module path github.com/openctemio/openctem/$OLD is gone: use .../$NEW" \
  "openctemio/openctem/$OLD(?![A-Za-z0-9_-])"
report "$OLD/ as a repository path is gone: the backend directory is $NEW/" \
  "(?<![$WORD])$OLD/(?=(?:$TOP))"
report "./$OLD, ../$OLD and \$VAR/$OLD as a repository path are gone: use $NEW" \
  "(?:\.\.?|\\$\\{?[A-Za-z0-9_]+\\}?)/$OLD/(?=(?:$TOP))"
# A checkout bind-mounted into a container (-v "$ROOT:/src"): /src/api is the old
# directory in the mount, not a runtime path of an image (those are /app/api,
# /opt/openctem/api, which stay).
report "a checkout mount path (/src/$OLD, /workspace/$OLD, /repo/$OLD, /work/$OLD) is gone: use $NEW" \
  "(?<![$WORD])/(?:src|workspace|repo|checkout|work|github/workspace)/$OLD(?![A-Za-z0-9_-])"

report "-C $OLD, cd $OLD, working-directory: $OLD and context: $OLD are gone: use $NEW" \
  "(?<![\\w./-])(?:-C|cd|pushd)\\s+(?:\./)?$OLD(?![\\w/-])|working-directory:\\s*(?:\./)?$OLD\\s*\$|\\b(?:context|working-directory|path|dir):\\s*(?:\./)?$OLD\\s*[,}]"

report "the directory as a bare word (TREE_PATHS, scan-ref, a docker build context, a :-default) is gone: use $NEW" \
  "TREE_PATHS[:=].*(?<=[\\s:=\"])$OLD(?=[\\s\"]|\$)|scan-ref:\\s*['\"]?$OLD['\"]?\\s*\$|docker (?:buildx )?build\\b.*\\s$OLD\\s*\\\\?\$|:-$OLD/"

report "an anchored regex or grep on the old directory (^$OLD/) is gone: use ^$NEW/" \
  "\\^$OLD/"

report "the directory as a find/ls/du/gofmt -l/git ls-files argument is gone: use $NEW" \
  "\\b(?:find|ls|du|gofmt -l|git ls-files)\\s+$OLD(?=\\s|\$)"

report "a Python path, a workflow-expression root or a bake context naming $OLD is gone: use $NEW" \
  "(?<!/)/\\s*[\"']$OLD[\"']\\s*(?:/|\\)|$)|os\\.path\\.join\\([^)]*,\\s*[\"']$OLD[\"']\\s*,\\s*[\"'](?:$TOP)|\\}\\}/$OLD/(?=(?:$TOP))|\\bcontext\\s*=\\s*\"$OLD\""

tracked="$(git ls-files -- "$OLD" | head -n 5 || true)"
if [[ -n "$tracked" ]]; then
  echo "::error::tracked files under $OLD/ (move them to $NEW/ with scripts/rename/catch-up.sh):"
  printf '%s\n' "$tracked"
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "The backend directory is $NEW/ (module github.com/openctemio/openctem/$NEW). On a branch from before the rename run: bash scripts/rename/catch-up.sh" >&2
  exit 1
fi
echo "OK: no tracked file names the old backend directory or module path."
