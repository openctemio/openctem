#!/usr/bin/env bash
# Edition fence: the Community build never contains extension code, and the
# open core builds from public sources only. Checks the git INDEX (what is
# tracked or staged), so the same script runs in CI and in pre-commit.
#
#   a. no tracked file under a web extension mount point (an extension's web
#      code is copied in by its own build; the mount points are empty here),
#      and .gitignore lists every mount point;
#   b. api/go.mod has no replace directive (the core always builds from public
#      sources and works as a dependency of a custom build, which imports
#      api/pkg/server and api/pkg/extension; docs/development/editions.md);
#   c. no web code imports a mount point directly (the default build reaches
#      it only through the @extension/* alias, which points at the empty
#      default), and the mount directory is named only in the web build
#      configs (tenant app and console);
#   d. no restricted word in any tracked text file or path. The word list is
#      not in this repository: CI passes it in FENCE_RESTRICTED_WORDS (a
#      secret), a local clone may keep it in .git/info/restricted-words (one
#      word per line, never tracked). Without a list, rule d is skipped.
#
# Output names file:line (or the path) and the rule, never the matched text of
# the word list. Run from the repository root: bash .github/scripts/check-edition-fence.sh
set -euo pipefail
set +x

# Mount points: tracked content here is a violation (git pathspec prefixes).
mount_paths=(
  'web/src/extensions/'
)
# Extension route groups, at any depth under a core layout group, e.g.
# web/src/app/(dashboard)/(extensions)/ (pages that use the core shell).
route_group_re='^web/(console/)?src/app/(.*/)?\(extensions\)/'
# The .gitignore lines that keep the mount points out of git.
ignore_lines=(
  '/web/src/extensions/'
  '/web/src/app/**/(extensions)/'
  '/web/console/src/app/**/(extensions)/'
)
# The web build configs (tenant app, console) that may name the mount directory.
web_switch_re='^web/(console/)?next\.config\.(ts|mjs|js)$'

status=0
fail() { echo "edition fence: $1" >&2; status=1; }

mapfile -t tracked < <(git ls-files)

# a. mount points are not tracked, and are ignored.
for f in "${tracked[@]}"; do
  for p in "${mount_paths[@]}"; do
    if [[ "$f" == "$p"* ]]; then fail "$f: extension mount point is tracked (rule a); extension code lives in its own repository"; fi
  done
  if [[ "$f" =~ $route_group_re ]]; then
    fail "$f: extension route group is tracked (rule a); extension code lives in its own repository"
  fi
done
if [[ -f .gitignore ]]; then
  for l in "${ignore_lines[@]}"; do
    grep -qxF -- "$l" .gitignore || fail ".gitignore: missing '$l' (rule a)"
  done
else
  fail ".gitignore missing (rule a)"
fi

# b. the core module builds from public sources only.
if [[ -f api/go.mod ]] && grep -Eq '^[[:space:]]*replace([[:space:]]|\()' api/go.mod; then
  fail "api/go.mod: has a replace directive (rule b); the core must build from public sources and work as a dependency"
fi

# c. web: no direct import of a mount point; mount directory named in the configs only.
direct_re="(from|import|require\\(|import\\()[[:space:]]*['\"](@/extensions(/|['\"])|(\\.\\./)+extensions(/|['\"])|\\./extensions(/|['\"])|[^'\"]*/src/extensions(/|['\"]))"
cfg_re="(^|[^A-Za-z0-9_-])src/extensions(/|['\"]|\$)"
for f in "${tracked[@]}"; do
  [[ "$f" == web/* && -f "$f" ]] || continue
  case "$f" in
    *.ts|*.tsx|*.js|*.jsx|*.mjs|*.cjs) ;;
    web/tsconfig*.json|web/console/tsconfig*.json) ;;
    *) continue ;;
  esac
  [[ "$f" == web/src/lib/i18n/dictionaries/* ]] && continue
  if grep -Eq "$direct_re" "$f"; then
    fail "$f: imports an extension mount point directly; use the @extension/* alias (rule c)"
  fi
  if grep -Eq "$cfg_re" "$f" && ! [[ "$f" =~ $web_switch_re ]]; then
    fail "$f: names the extension mount directory; only the web build configs may (rule c)"
  fi
done

# d. restricted words in paths and content (list from the environment only).
words_file=""
cleanup() { [[ -n "$words_file" ]] && rm -f -- "$words_file"; return 0; }
trap cleanup EXIT
if [[ -n "${FENCE_RESTRICTED_WORDS:-}" ]]; then
  words_file="$(mktemp)"
  tr ', ' '\n\n' <<<"$FENCE_RESTRICTED_WORDS" | sed '/^$/d' > "$words_file"
elif git_dir="$(git rev-parse --git-dir 2>/dev/null)" && [[ -s "$git_dir/info/restricted-words" ]]; then
  words_file="$(mktemp)"
  sed '/^[[:space:]]*$/d; /^#/d' "$git_dir/info/restricted-words" > "$words_file"
fi
if [[ -n "$words_file" && -s "$words_file" ]]; then
  while IFS= read -r f; do
    [[ -n "$f" ]] && fail "$f: path contains a restricted word (rule d)"
  done < <(printf '%s\n' "${tracked[@]}" | grep -iF -f "$words_file" || true)
  while IFS= read -r hit; do
    [[ -n "$hit" ]] && fail "$hit: contains a restricted word (rule d)"
  done < <(git grep --cached -I -i -n -F -f "$words_file" -- . | awk -F: '{print $1 ":" $2}' || true)
else
  echo "edition fence: no restricted-word list in this environment; rule d skipped" >&2
fi

if (( status )); then
  echo "edition fence: see api/docs/development/editions.md" >&2
else
  echo "edition fence: ok"
fi
exit "$status"
