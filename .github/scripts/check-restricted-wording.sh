#!/usr/bin/env bash
# Restricted wording: refuses text that matches a rule list kept outside this
# repository. The rules come from the RESTRICTED_WORDING_RULES environment
# variable only (CI fills it from a repository secret of the same name). When
# it is unset or holds no rule (forks, Dependabot, a clone without it) the
# check is skipped with a notice and passes.
#
# Modes:
#   check-restricted-wording.sh --diff <base> <head>   added lines of base..head
#                                                      (two-dot diff: pass the
#                                                      merge base as base)
#   check-restricted-wording.sh --staged               added lines of the index
#   check-restricted-wording.sh --text <file>...       whole files (a commit
#                                                      message, a pull request
#                                                      title and body, a
#                                                      branch name)
#   check-restricted-wording.sh --tree                 every tracked file
#
# RESTRICTED_WORDING_RULES, one entry per line:
#   <regex>          an extended regular expression, matched case-insensitively
#   cs: <regex>      the same, matched case-sensitively
#   allow: <phrase>  a fixed, case-insensitive phrase removed from a line
#                    before the rules are tried; the rest of the line is
#                    still checked
#   path: <glob>     files skipped in --diff, --staged and --tree; `*` matches
#                    any characters, `/` included
# Blank lines and lines starting with `#` are ignored. --text applies the
# phrases and ignores the paths.
#
# Output names file:line only, never a rule or the matched text. Never run
# this with `set -x`: the rules would be traced into the log. Every input is
# read as data by git, grep, sed and awk; nothing from it is evaluated.
set -euo pipefail
set +x

usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[[ $# -ge 1 ]] || usage
mode="$1"; shift
case "$mode" in
  --diff) [[ $# -eq 2 ]] || usage ;;
  --staged | --tree) [[ $# -eq 0 ]] || usage ;;
  --text) [[ $# -ge 1 ]] || usage ;;
  *) usage ;;
esac

work="$(mktemp -d)"
trap 'find "$work" -delete' EXIT
chmod 700 "$work"
ci="$work/ci"; cs="$work/cs"; phrases="$work/phrases"; paths="$work/paths"
: >"$ci"; : >"$cs"; : >"$phrases"; : >"$paths"
printf '%s\n' "${RESTRICTED_WORDING_RULES:-}" | tr -d '\r' |
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | grep -v -E '^(#|$)' >"$work/all" || true
grep -E '^cs:' "$work/all" | sed -E 's/^cs:[[:space:]]*//' | grep -v '^$' >"$cs" || true
grep -E '^allow:' "$work/all" | sed -E 's/^allow:[[:space:]]*//' | grep -v '^$' >"$phrases" || true
grep -E '^path:' "$work/all" | sed -E 's/^path:[[:space:]]*//' | grep -v '^$' >"$paths" || true
grep -v -E '^(cs|allow|path):' "$work/all" >"$ci" || true

if [[ ! -s "$ci" && ! -s "$cs" ]]; then
  echo "restricted wording: no rules in this environment; skipped" >&2
  exit 0
fi

# scan <filter>: reads "path<TAB>line<TAB>text" rows on stdin. With filter=1 a
# row whose path matches a `path:` glob is skipped. Allowed phrases are removed
# from the text, then every rule is tried; prints "path:line" once per hit.
scan() {
  awk -F'\t' -v phrases="$phrases" -v paths="$paths" -v ci="$ci" -v cs="$cs" -v filter="$1" '
    function glob2re(g,    i, c, r) {
      r = "^"
      for (i = 1; i <= length(g); i++) {
        c = substr(g, i, 1)
        if (c == "*") r = r ".*"
        else if (index("\\.^$+?()[]{}|", c) > 0) r = r "\\" c
        else r = r c
      }
      return r "$"
    }
    BEGIN {
      while ((getline p < phrases) > 0) if (p != "") ph[++np] = tolower(p)
      while ((getline p < paths) > 0) if (p != "") pa[++npa] = glob2re(p)
      while ((getline p < ci) > 0) if (p != "") pci[++nci] = p
      while ((getline p < cs) > 0) if (p != "") pcs[++ncs] = p
    }
    {
      path = $1
      if (filter == 1) {
        if (!(path in skip)) {
          skip[path] = 0
          for (i = 1; i <= npa; i++) if (path ~ pa[i]) { skip[path] = 1; break }
        }
        if (skip[path]) next
      }
      text = substr($0, length($1) + length($2) + 3); low = tolower(text)
      for (i = 1; i <= np; i++) {
        n = length(ph[i])
        while ((at = index(low, ph[i])) > 0) {
          low = substr(low, 1, at - 1) " " substr(low, at + n)
          text = substr(text, 1, at - 1) " " substr(text, at + n)
        }
      }
      for (i = 1; i <= nci; i++) if (low ~ pci[i]) { print path ":" $2; bad = 1; next }
      for (i = 1; i <= ncs; i++) if (text ~ pcs[i]) { print path ":" $2; bad = 1; next }
    }
    END { exit bad ? 1 : 0 }'
}

# added_lines <git diff args...>: "path<TAB>line<TAB>text" for every added line
# of a text file.
added_lines() {
  git -c core.quotepath=off diff --no-color --no-ext-diff --no-renames -U0 --diff-filter=AM "$@" |
    awk '
      /^diff --git / { path = ""; next }
      /^\+\+\+ b\// { path = substr($0, 7); next }
      /^\+\+\+ / { path = ""; next }
      /^Binary files / { path = ""; next }
      /^@@ / { split($3, a, ","); n = substr(a[1], 2) + 0; next }
      /^\+/ { if (path != "") printf "%s\t%d\t%s\n", path, n, substr($0, 2); n++; next }'
}

rc=0
case "$mode" in
  --diff)
    out="$(added_lines "$1" "$2" | scan 1)" || rc=$?
    ;;
  --staged)
    out="$(added_lines --cached | scan 1)" || rc=$?
    ;;
  --text)
    out="$(for f in "$@"; do
      LABEL="$(basename "$f")" awk '{ printf "%s\t%d\t%s\n", ENVIRON["LABEL"], NR, $0 }' "$f"
    done | scan 0)" || rc=$?
    ;;
  --tree)
    # git grep selects the candidate lines (path:line:text) of tracked text
    # files; scan then applies the exceptions to them.
    out="$({
      if [[ -s "$ci" ]]; then git -c core.quotepath=off grep -I -n -i -E -f "$ci" -- . || true; fi
      if [[ -s "$cs" ]]; then git -c core.quotepath=off grep -I -n -E -f "$cs" -- . || true; fi
    } | awk '{ a = index($0, ":"); rest = substr($0, a + 1); b = index(rest, ":")
               printf "%s\t%s\t%s\n", substr($0, 1, a - 1), substr(rest, 1, b - 1), substr(rest, b + 1) }' |
      scan 1)" || rc=$?
    ;;
esac

if [[ "$rc" -eq 0 ]]; then
  echo "restricted wording: ok"
  exit 0
fi
echo "restricted wording: found at (the rules are not in this repository; ask a maintainer):" >&2
printf '%s\n' "$out" | sort -u | sed 's/^/  /' >&2
exit 1
