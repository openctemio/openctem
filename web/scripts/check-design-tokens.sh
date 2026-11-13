#!/usr/bin/env bash
#
# Fail a pull request that ADDS a hard-coded design value where a token exists
# (research/513 B.5). Same model as check-palette-drift.sh and
# check-page-anatomy.sh: only lines added relative to the merge base of the
# tenant app (src/) and the platform console (console/src/) are read, so
# existing code is untouched and there is no baseline file to go stale. Run by
# check-page-anatomy.sh, so Web CI runs it in the "Check page anatomy" step.
#
#   1. A raw colour: #rrggbb, rgb(), hsl(), oklch() or an arbitrary [#abc]
#      class. Colours live in src/styles/theme.css (and the validated chart
#      palette); use the semantic tokens (bg-card, text-muted-foreground,
#      border-strong, bg-hov, ...).
#   2. An arbitrary radius, shadow, line height, weight or tracking
#      (rounded-[..], shadow-[..], leading-[..], font-[..], tracking-[..]):
#      radius 4 / 6 / 8 by role (rounded-sm / rounded-md / rounded-lg,
#      rounded-dialog), one overlay shadow (shadow-overlay), line heights come
#      with the type roles.
#   3. Weight 700 or more (font-bold, font-extrabold, font-black): weights
#      are 400, 500 and 600.
#   4. A height or size on a kit control's className (<Button className="h-7">,
#      <Input className="h-11">, SelectTrigger, ToggleGroupItem, TabsTrigger):
#      the control scale ("Sizes" in web/docs/ui-style-contract.md) is set by
#      the kit, never per call site.
#   5. The type ratchet: in a directory listed in scripts/type-migrated.txt, a
#      raw Tailwind text size (text-xs, text-sm, text-base, text-lg, text-xl,
#      text-2xl ...). Use the type roles: text-cap, text-cap-m, text-code,
#      text-dense, text-body, text-card, text-section, text-dialog, text-page,
#      text-figure. The list only grows, one directory per migrated page.
#
# Literal screen text is guarded separately, file by file, by
# src/lib/__tests__/literal-ui-text-ratchet.test.ts.
#
# Escape hatch for a real exception: `design-ok: <reason>` on the line.
set -euo pipefail

BASE_REF="${1:-origin/develop}"
here="$(cd "$(dirname "$0")" && pwd)"

case "${BASE_REF##*/}" in
  main | master)
    echo "check-design-tokens: base is '${BASE_REF}' (release merge); skipping."
    exit 0
    ;;
esac

if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  if [[ -n "${CI:-}" ]]; then
    echo "check-design-tokens: base ref '$BASE_REF' not found (needs fetch-depth: 0)." >&2
    exit 1
  fi
  echo "check-design-tokens: base ref '$BASE_REF' not found; skipping (not CI)." >&2
  exit 0
fi

merge_base="$(git merge-base "$BASE_REF" HEAD)"

# Added lines as "<path relative to web/>:<line>". Tests, the token file and
# the chart palette are where raw values belong.
added="$(git diff -U0 "$merge_base"...HEAD -- 'src/*.tsx' 'src/*.ts' 'src/*.css' \
  'console/src/*.tsx' 'console/src/*.ts' 'console/src/*.css' \
  | awk '/^\+\+\+ b\//{f=substr($0,7); sub(/^web\//, "", f); next} /^\+/{print f ":" substr($0,2)}' \
  | grep -v 'design-ok:' \
  | grep -Ev '/__tests__/|\.test\.tsx?:|\.spec\.tsx?:' \
  | grep -Ev '^src/styles/theme\.css:|^src/lib/chart-palette' || true)"

if [[ -z "$added" ]]; then
  echo "check-design-tokens: no added source lines."
  exit 0
fi

fail=0
report() { # <title> <lines> <advice>
  fail=1
  printf '\n%s\n\n%s\n\n%s\n' "$1" "$(printf '%s\n' "$2" | cut -c1-200)" "$3" >&2
}

hits="$(printf '%s\n' "$added" \
  | grep -E '#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?\b|\[#[0-9a-fA-F]{3,4}\]|\b(rgba?|hsla?|oklch|oklab)\(' || true)"
[[ -n "$hits" ]] && report "A raw colour:" "$hits" \
  "Colours live in src/styles/theme.css. Use a semantic token class (bg-card, text-muted-foreground, border-strong, bg-hov, bg-sel, text-signal-text, ...) or var(--token) in CSS."

hits="$(printf '%s\n' "$added" | grep -E '\b(rounded(-[a-z]+)?|shadow|leading|font|tracking)-\[' || true)"
[[ -n "$hits" ]] && report "An arbitrary radius, shadow, line height, weight or tracking:" "$hits" \
  "Radius by role: rounded-sm 4, rounded-md 6 (controls, chips), rounded-lg 8 (cards, menus), rounded-dialog. One overlay shadow: shadow-overlay. Line height and weight come with the type role (text-dense, text-body, text-card, ...)."

hits="$(printf '%s\n' "$added" | grep -E '\bfont-(bold|extrabold|black)\b' || true)"
[[ -n "$hits" ]] && report "Weight 700 or more:" "$hits" \
  "Weights are 400, 500 (font-medium, emphasis inside text) and 600 (font-semibold, titles and figures); the type roles carry their own."

KIT_CONTROL='<(Button|Input|SelectTrigger|ToggleGroupItem|TabsTrigger)\b'
hits="$(printf '%s\n' "$added" | grep -Ev '^(console/)?src/components/ui/' \
  | grep -E "${KIT_CONTROL}[^>]*className=[^>]*(^|[\"'\` {:])(h|size|min-h)-([0-9]|\[|control)" || true)"
[[ -n "$hits" ]] && report "A height on a kit control:" "$hits" \
  "The kit sets the control height (\"Sizes\" in web/docs/ui-style-contract.md). Remove the h-*/size-* from the call site; a real exception says why with design-ok."

migrated="$here/type-migrated.txt"
if [[ -f "$migrated" ]]; then
  dirs="$(grep -Ev '^[[:space:]]*(#|$)' "$migrated" | sed -E 's#/*$#/#' | paste -sd'|' - || true)"
  if [[ -n "$dirs" ]]; then
    hits="$(printf '%s\n' "$added" | grep -E "^(${dirs//./\\.})" \
      | grep -E "(^|[\"'\` {:])text-(xs|sm|base|lg|[2-9]?xl)\b" || true)"
    [[ -n "$hits" ]] && report "A raw text size in a migrated directory (scripts/type-migrated.txt):" "$hits" \
      "Use the type roles: text-cap / text-cap-m 12, text-code 12 mono, text-dense 13, text-body 14, text-card 14 600, text-section 16, text-dialog 20, text-page 24, text-figure 24."
  fi
fi

if [[ "$fail" = 0 ]]; then
  echo "check-design-tokens: no new hard-coded design values."
else
  printf '\nA real exception can be annotated on the line: // design-ok: <reason>\n' >&2
fi
exit "$fail"
