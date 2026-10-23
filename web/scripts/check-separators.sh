#!/usr/bin/env bash
#
# Fail a pull request that ADDS a separator glyph to UI text (research/248).
#
# Same model as check-palette-drift.sh: only lines added relative to the merge
# base are checked, so existing code is untouched and there is no baseline file
# to go stale. The call-site migration removes the old ones in later PRs.
#
# Why: a middle dot between every fact reads as generated UI, a joined string
# truncates and wraps badly (a wrapped line can start with the dot), and the
# glyph is copied on paste and read aloud by some screen readers. Spacing does
# the separating:
#
#   rendered UI   <MetaLine items={[a, b, c]} />   (12px gap, sr-only ", ")
#   plain text    formatList(parts, locale)          (Intl.ListFormat)
#   two parts     <LabelSegments> or code + name in separate spans
#   titles        one phrase; context goes in a description or badge
#
# Rules, on lines added in src/**/*.{ts,tsx} (not tests) and in the i18n
# dictionaries:
#   1. no `·` `•` `∙` `⋅` (a run of three or more bullets is a credential mask
#      and is allowed)
#   2. no `.join(' — ')`, `.join(' | ')` and the like
#   3. no spaced ` — ` in a dictionary value or in code outside a comment: use
#      two elements, a colon, a comma or a full stop. The lone `—` empty-cell
#      placeholder is not affected.
#   4. no ` | ` between two interpolations or tags used as a text separator
#
# Escape hatch in code: `separator-ok: <reason>` on the line (the MetaLine and
# formatList implementations, a fixture asserting absence). JSON has no
# comments, so a dictionary value never gets an exception.
set -euo pipefail

BASE_REF="${1:-origin/develop}"

case "${BASE_REF##*/}" in
  main | master)
    echo "check-separators: base is '${BASE_REF}' (release merge); skipping."
    exit 0
    ;;
esac

if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  if [[ -n "${CI:-}" ]]; then
    echo "check-separators: base ref '$BASE_REF' not found (needs fetch-depth: 0)." >&2
    exit 1
  fi
  echo "check-separators: base ref '$BASE_REF' not found; skipping (not CI)." >&2
  exit 0
fi

merge_base="$(git merge-base "$BASE_REF" HEAD)"

# Added lines as "file:text", tests excluded.
added="$(git diff -U0 "$merge_base"...HEAD -- 'src/*.tsx' 'src/*.ts' 'src/lib/i18n/dictionaries/*.json' \
  | awk '/^\+\+\+ b\//{f=substr($0,7); next} /^\+/{print f ":" substr($0,2)}' \
  | grep -v 'separator-ok:' | grep -v '/__tests__/' | grep -Ev '\.test\.tsx?:' || true)"

if [[ -z "$added" ]]; then
  echo "check-separators: no added source lines."
  exit 0
fi

fail=0
report() { # <title> <lines> <advice>
  fail=1
  printf '\n%s\n\n%s\n\n%s\n' "$1" "$(printf '%s\n' "$2" | cut -c1-200)" "$3" >&2
}

# Print the added lines whose text matches <ERE>. A trailing // comment and a
# credential mask (three or more bullets) are ignored; with skip=1, lines that
# are only a comment are ignored too.
scan() { # <ERE> [skip]
  printf '%s\n' "$added" | SEP_RE="$1" awk -v skip="${2:-0}" '
    BEGIN { re = ENVIRON["SEP_RE"] }
    { i = index($0, ":"); f = substr($0, 1, i - 1); t = substr($0, i + 1)
      u = t; sub(/ \/\/ .*$/, "", u); gsub(/(•)(•)(•)+/, "", u)
      if (skip == 1 && u ~ /^[[:space:]]*(\/\/|\/\*|\*|\{\/\*)/) next
      if (u ~ re) print f ":" t }'
}

hits="$(scan "·|•|∙|⋅" 1)"
[[ -n "$hits" ]] && report "This branch adds a separator glyph to UI text:" "$hits" \
  "Spacing separates, not a mark. Rendered rows: <MetaLine items={[...]}/>. Plain text (title attribute, toast, CSV): formatList(parts, locale). Two parts of one label: separate spans. One translation key per item, never a key for the whole run. Why: research/248 (it wraps and truncates badly, is copied on paste, and is read aloud by some screen readers)."

hits="$(scan "join\\([[:space:]]*['\"\`][[:space:]]*(—|–|\\||·|•)")"
[[ -n "$hits" ]] && report "This branch joins text with a separator character:" "$hits" \
  "Use <MetaLine items={[...]}/> for rendered UI or formatList(parts, locale) for plain text."

hits="$(scan ' — ' 1)"
[[ -n "$hits" ]] && report "This branch adds a spaced em dash to a string or JSX text:" "$hits" \
  "Use two elements (title and description), 'Label: description', a comma or a full stop. The lone '—' empty-cell placeholder stays."

hits="$(scan '\} \| \$\{|>[[:space:]]*\|[[:space:]]*<')"
[[ -n "$hits" ]] && report "This branch uses a pipe as a text separator:" "$hits" \
  "Use <MetaLine items={[...]}/> or formatList(parts, locale)."

if [[ $fail = 0 ]]; then
  echo "check-separators: no new separator glyphs."
fi
exit "$fail"
