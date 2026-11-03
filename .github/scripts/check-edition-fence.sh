#!/usr/bin/env bash
# Edition fence: the Community build must never contain Enterprise code, and
# the open core never names the commercial brand. Checks the git INDEX (what
# is tracked or staged), so the same script runs in CI and in pre-commit.
#
#   a. no tracked file under an Enterprise overlay path (the overlay is
#      compiled in from a private repository; api/ee/README.md is the only
#      tracked file there), and .gitignore lists every overlay path;
#   b. no Go file imports the overlay (an api/ee package or a private
#      module) unless it carries the ee build tag;
#   c. the ee build tag appears in exactly one file (the build switch);
#   d. no web code imports the overlay directly (the default build reaches it
#      only through the @extension/* alias, which points at the empty
#      default), and the overlay directory is named only in the web build
#      configs (tenant app and console);
#   e. no commercial brand name in any tracked text file or path.
#
# Output names file:line (or the path) and the rule, never the matched text of
# the brand list. Run from the repository root: bash .github/scripts/check-edition-fence.sh
set -euo pipefail
set +x

# Overlay paths: tracked content here is a violation (git pathspec prefixes).
overlay_paths=(
  'api/ee/'
  'web/src/ee/'
  'web/src/app/(ee)/'
  'web/console/src/ee/'
  'web/console/src/app/(ee)/'
)
overlay_keep='api/ee/README.md'
# The .gitignore lines that keep the overlay out of git.
ignore_lines=(
  '/api/ee/*'
  '!/api/ee/README.md'
  '/web/src/ee/'
  '/web/src/app/(ee)/'
  '/web/console/src/ee/'
  '/web/console/src/app/(ee)/'
)
# The one file that may carry the ee build tag (the build switch).
switch_file='api/cmd/server/edition_ee.go'
# The web build configs (tenant app, console) that may name the overlay directory.
web_switch_re='^web/(console/)?next\.config\.(ts|mjs|js)$'
# Commercial brand words (case-insensitive). Kept here, not in docs.
brand_words=(exploop)
# Files that hold the list itself or test it.
self_files=(.github/scripts/check-edition-fence.sh .github/scripts/check-edition-fence.test.sh)

status=0
fail() { echo "edition fence: $1" >&2; status=1; }

mapfile -t tracked < <(git ls-files)
is_self() { local f; for f in "${self_files[@]}"; do [[ "$1" == "$f" ]] && return 0; done; return 1; }

# a. overlay paths are not tracked, and are ignored.
for f in "${tracked[@]}"; do
  [[ "$f" == "$overlay_keep" ]] && continue
  for p in "${overlay_paths[@]}"; do
    if [[ "$f" == "$p"* ]]; then fail "$f: Enterprise overlay path is tracked (rule a); the overlay lives only in the private repository"; fi
  done
done
if [[ -f .gitignore ]]; then
  for l in "${ignore_lines[@]}"; do
    grep -qxF -- "$l" .gitignore || fail ".gitignore: missing '$l' (rule a)"
  done
else
  fail ".gitignore missing (rule a)"
fi
# a (nested). Overlay route groups may sit under a core layout group, e.g.
# web/src/app/(dashboard)/(ee)/: none may be tracked, and both are ignored.
nested_re='^web/(console/)?src/app/(.*/)?\(ee\)/'
for f in "${tracked[@]}"; do
  [[ "$f" =~ $nested_re ]] && fail "$f: Enterprise overlay route group is tracked (rule a); the overlay lives only in the private repository"
done
for l in '/web/src/app/**/(ee)/' '/web/console/src/app/**/(ee)/'; do
  [[ -f .gitignore ]] && ! grep -qxF -- "$l" .gitignore && fail ".gitignore: missing '$l' (rule a)"
done

# b + c. Go: overlay imports and the ee build tag.
tag_re='^//[[:space:]]*(go:build|\+build).*(^|[^A-Za-z0-9_])ee([^A-Za-z0-9_]|$)'
imp_re='"(github\.com/openctemio/openctem/api/ee(/[^"]*)?|github\.com/exploopio/[^"]*)"'
for f in "${tracked[@]}"; do
  [[ "$f" == *.go && -f "$f" ]] || continue
  has_tag=0
  if head -n 30 "$f" | grep -Eq "$tag_re"; then has_tag=1; fi
  if (( has_tag )) && [[ "$f" != "$switch_file" ]]; then
    fail "$f: carries the ee build tag, which only $switch_file may (rule c)"
  fi
  if (( ! has_tag )) && grep -Eq "$imp_re" "$f"; then
    fail "$f: imports the Enterprise overlay without the ee build tag (rule b)"
  fi
done

# d. web: no direct import of the overlay; overlay directory named in one config.
direct_re="(from|import|require\\(|import\\()[[:space:]]*['\"](@/ee(/|['\"])|@console/ee(/|['\"])|(\\.\\./)+ee(/|['\"])|\\./ee(/|['\"])|[^'\"]*/src/ee(/|['\"]))"
cfg_re="(^|[^A-Za-z0-9_-])src/ee(/|['\"]|\$)"
for f in "${tracked[@]}"; do
  [[ "$f" == web/* && -f "$f" ]] || continue
  case "$f" in
    *.ts|*.tsx|*.js|*.jsx|*.mjs|*.cjs) ;;
    web/tsconfig*.json|web/console/tsconfig*.json) ;;
    *) continue ;;
  esac
  [[ "$f" == web/src/lib/i18n/dictionaries/* ]] && continue
  if grep -Eq "$direct_re" "$f"; then
    fail "$f: imports the Enterprise overlay directly; use the @extension/* alias (rule d)"
  fi
  if grep -Eq "$cfg_re" "$f" && ! [[ "$f" =~ $web_switch_re ]]; then
    fail "$f: names the Enterprise overlay directory; only the web build config may (rule d)"
  fi
done

# e. brand words in paths and content.
for w in "${brand_words[@]}"; do
  while IFS= read -r f; do
    is_self "$f" || fail "$f: path names the commercial brand (rule e)"
  done < <(printf '%s\n' "${tracked[@]}" | grep -iF -- "$w" || true)
  while IFS= read -r hit; do
    [[ -n "$hit" ]] && fail "$hit: names the commercial brand (rule e)"
  done < <(git grep --cached -I -i -n -F -e "$w" -- . ':(exclude).github/scripts/check-edition-fence.sh' ':(exclude).github/scripts/check-edition-fence.test.sh' | awk -F: '{print $1 ":" $2}' || true)
done

if (( status )); then
  echo "edition fence: see api/docs/development/editions.md" >&2
else
  echo "edition fence: ok"
fi
exit "$status"
