#!/usr/bin/env bash
#
# Fail a pull request that ADDS page-anatomy or type-scale drift (research/244).
#
# Same model as check-palette-drift.sh: only lines added relative to the merge
# base are checked, so existing code is untouched and there is no baseline file
# to go stale. Each rule names the shared primitive to use instead.
#
#   1. A new StatsCard: a page's numbers go in one MetricStrip.
#   2. A new ad-hoc metric tile: a big number (text-2xl..4xl + bold/semibold)
#      outside the primitives that own one (MetricStrip, PageHeader, the
#      dashboard kit). A hand-built tile grid regrows the tile wall.
#   3. An arbitrary text size (text-[10px], text-[0.8rem]): use the scale
#      (text-xs 12px meta, text-sm 14px body, text-base, text-lg, ...).
#   4. Two different text sizes on one line of JSX (`text-xs` beside
#      `text-sm`): one size per line of metadata; a label is muted, not
#      smaller. Responsive variants (sm:text-base) are fine.
#   5. A margin on a route tab strip (<SectionTabs className="mt-4 mb-0">):
#      PageStack owns the gap above and below the tabs.
#   6. A new SegmentedLens: the state of a list's rows is a filter token
#      (FilterSelect, or the Add-filter chips); a view mode is ViewSwitcher.
#   7. A tab icon with its own classes (<TabsTrigger> then <Icon className=..>):
#      tab icons are drawn by the strip, 16px in the tab's text colour; route
#      tabs take them from SectionTab.icon.
#   8. A second tab row: a file that renders route tabs and adds a TabsList.
#
# Escape hatch for a real exception: `anatomy-ok: <reason>` on the line.
set -euo pipefail

BASE_REF="${1:-origin/develop}"

case "${BASE_REF##*/}" in
  main | master)
    echo "check-page-anatomy: base is '${BASE_REF}' (release merge); skipping."
    exit 0
    ;;
esac

if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  if [[ -n "${CI:-}" ]]; then
    echo "check-page-anatomy: base ref '$BASE_REF' not found (needs fetch-depth: 0)." >&2
    exit 1
  fi
  echo "check-page-anatomy: base ref '$BASE_REF' not found; skipping (not CI)." >&2
  exit 0
fi

merge_base="$(git merge-base "$BASE_REF" HEAD)"

# Added lines, each prefixed with its file, from component sources only. The
# primitives that legitimately own a big number are excluded from rule 2 below.
added="$(git diff -U0 "$merge_base"...HEAD -- 'src/*.tsx' \
  | awk '/^\+\+\+ b\//{f=substr($0,7); next} /^\+/{print f ":" substr($0,2)}' \
  | grep -v 'anatomy-ok:' | grep -v '/__tests__/' | grep -v '\.test\.tsx:' || true)"

if [[ -z "$added" ]]; then
  echo "check-page-anatomy: no added component lines."
fi

fail=0
report() { # <title> <lines> <advice>
  fail=1
  printf '\n%s\n\n%s\n\n%s\n' "$1" "$(printf '%s\n' "$2" | cut -c1-200)" "$3" >&2
}

hits="$(printf '%s\n' "$added" | grep -E '<StatsCard\b' || true)"
[[ -n "$hits" ]] && report "New StatsCard tiles:" "$hits" \
  "Put the page's numbers in one MetricStrip (features/shared): every tile a link (href) or a filter toggle (onClick), at most 5, no corner icons."

OWNERS='(features/shared/components/metric-strip\.tsx|features/shared/components/page-header\.tsx|components/dashboard-kit/|app/\(auth\)/|features/legal/)'
hits="$(printf '%s\n' "$added" | grep -Ev "^(web/)?src/${OWNERS}" \
  | grep -E '\btext-(2xl|3xl|4xl)\b' | grep -E '\bfont-(bold|semibold)\b' || true)"
[[ -n "$hits" ]] && report "New ad-hoc metric tile (a big bold number):" "$hits" \
  "Use MetricStrip for a page's numbers, or a dashboard-kit widget on a dashboard."

hits="$(printf '%s\n' "$added" | grep -E '\btext-\[[0-9.]+(px|rem|em)\]' || true)"
[[ -n "$hits" ]] && report "Arbitrary text size:" "$hits" \
  "Use the type scale: text-xs (12px, meta and labels), text-sm (14px, body), text-base, text-lg, text-xl, text-2xl. Nothing under 12px."

# Unprefixed size utilities only: a space, quote, backtick or brace before them.
hits="$(printf '%s\n' "$added" | while IFS= read -r line; do
  n="$(printf '%s' "$line" | grep -oE "(^|[\"'\` {])text-(xs|sm|base|lg|xl|2xl)\b" \
    | sed -E 's/.*(text-[a-z0-9]+)/\1/' | sort -u | wc -l)"
  [[ "$n" -gt 1 ]] && printf '%s\n' "$line"
done || true)"
[[ -n "$hits" ]] && report "Two text sizes on one line:" "$hits" \
  "One size per line of metadata. Use MetaLine / KeyValueList (features/shared): labels are muted, not smaller."

hits="$(printf '%s\n' "$added" | grep -E '<(Gated)?SectionTabs\b.*className="[^"]*\bm[tyb]-' || true)"
[[ -n "$hits" ]] && report "Margin on a route tab strip:" "$hits" \
  "Put the page's blocks in a PageStack (features/shared); it owns the 16px under the header and the 20px under the tabs."

hits="$(printf '%s\n' "$added" | grep -E '<SegmentedLens\b' || true)"
[[ -n "$hits" ]] && report "New SegmentedLens:" "$hits" \
  "A list's state (status, kind) is a filter token: FilterSelect (features/shared) at the start of the toolbar, value in the URL, counts in its menu. A view mode of the same rows is ViewSwitcher at the toolbar end."

# Rule 7 needs the line after a <TabsTrigger> opening, within one file.
hits="$(git diff -U0 "$merge_base"...HEAD -- 'src/*.tsx' | awk '
  /^\+\+\+ b\//{f=substr($0,7); prev=""; next}
  /^\+/{ line=substr($0,2)
    if (line ~ /anatomy-ok:/) { prev=""; next }
    if (line ~ /<TabsTrigger[^>]*>[[:space:]]*<[A-Z][A-Za-z0-9]*[^>]*className=/) print f ":" line
    else if (prev ~ /<TabsTrigger/ && prev !~ /\/>/ && line ~ /^[[:space:]]*<[A-Z][A-Za-z0-9]*[[:space:]][^>]*className=/) print f ":" line
    prev=line; next }
  { prev="" }' | grep -v '/__tests__/' || true)"
[[ -n "$hits" ]] && report "A tab icon with its own classes:" "$hits" \
  "Tab icons are optional, all or none in a strip, 16px in the tab's text colour, never coloured. Give the icon no className; on route tabs set SectionTab.icon."

hits="$(printf '%s\n' "$added" | grep -E '<TabsList\b' | while IFS= read -r line; do
  f="${line%%:*}"
  f="${f#web/}"
  [[ -f "$f" ]] && grep -qE '<(Gated)?SectionTabs\b|SectionTabs\b' "$f" && printf '%s\n' "$line"
done || true)"
[[ -n "$hits" ]] && report "A second tab row under route tabs:" "$hits" \
  "One tab row per page (research/249 R21). A filter or state of the rows is a FilterSelect in the toolbar; another view is ViewSwitcher; a sub-page is a route tab."

if [[ "$fail" = 0 ]]; then
  echo "check-page-anatomy: no new anatomy or type-scale drift."
else
  printf '\nA real exception can be annotated on the line: // anatomy-ok: <reason>\n' >&2
fi
exit "$fail"
