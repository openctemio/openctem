#!/usr/bin/env bash
#
# Fail a pull request that ADDS hardcoded Tailwind palette classes.
#
# Why a gate rather than a cleanup: the count went from 4,825 to 5,323 in one
# month while `dark:` variants also grew (561 -> 919). So this is not neglect —
# people are styling carefully, just not through the token layer. A one-off
# cleanup against that gradient regrows, and the two numbers moving together are
# the evidence.
#
# What is actually at stake: src/styles/theme.css defines semantic tokens
# (bg-background, text-muted-foreground, border-border, …) that carry their own
# dark value. A literal `text-gray-500` does not, so each one is a place dark mode
# has to be remembered by hand. That is why the "dark-mode tail" keeps coming back
# in UI reviews — it is not one tail, it is 5,323 individual decisions.
#
# Scope: only lines ADDED relative to the merge base. That keeps the message
# actionable — it names your lines, not a 5,000-line backlog — and means there is
# no baseline file to drift out of date. Existing code is deliberately untouched.
#
# Escape hatch: annotate the line with `palette-ok:` and a reason, for cases the
# tokens genuinely do not cover — brand colours, third-party embeds, or a set of
# distinct accents (the integrations category cards need eight; the semantic
# tokens intentionally do not provide eight).
#
# Second rule, same step: no coloured accent stripes on cards, tiles or rows (owner
# rule 2026-10-22, "they look too AI"). An added line is refused when it puts a
# colour on one side only (`border-l-primary`, `border-t-warning`, `border-l-4
# border-primary`, `border-t-red-500`). State is a status pill or dot plus text, an
# icon, or the value's own semantic colour; cards keep a uniform 1px neutral border.
# Neutral sides (`border-l-2 border-muted`, an indent rule) are fine. Allow a real
# exception with `stripe-ok: <reason>` on the line.
set -euo pipefail

BASE_REF="${1:-origin/develop}"

# A release merge is not a place to gate added lines.
#
# The gate diffs against the PR's base. On a normal PR that base is `develop`,
# so "added" means the handful of lines this branch wrote. On a release PR the
# base is `main`, so "added" means every line merged since the last tag — for
# the first release this gate ever saw, that was 140 commits and a month of
# work. It reported ~5,000 lines of pre-existing styling as if the release
# author had just written them, and it would do that on every release forever.
#
# Every one of those lines already passed this gate on its way into develop.
# Re-checking them at release time is double jeopardy, and it is unactionable:
# the person cutting the release cannot go fix another month of other people's
# styling, so the only available move is to override the check — which is how a
# gate stops meaning anything.
#
# This is not the "silently exits 0" failure the base-ref branch below guards
# against. That one hides a broken gate; this one states a deliberate scope.
case "${BASE_REF##*/}" in
  main | master)
    echo "check-palette-drift: base is '${BASE_REF}', so this is a release merge."
    echo "Skipping: every commit in this range was already gated against develop."
    exit 0
    ;;
esac

# Tailwind's palette families. Semantic names (background, foreground, muted,
# border, primary, destructive, …) are deliberately absent — those are the ones
# this gate is steering people toward.
PALETTE='(slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)'
PROPS='(bg|text|border|ring|fill|stroke|from|via|to|divide|outline|shadow|accent|caret|decoration|placeholder)'

if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  # In CI this must be loud. A gate that cannot resolve its base and exits 0 is
  # indistinguishable from a gate that passed — that is how checks quietly stop
  # running for months. Locally, skipping is the useful behaviour.
  if [[ -n "${CI:-}" ]]; then
    echo "check-palette-drift: base ref '$BASE_REF' not found." >&2
    echo "The checkout needs fetch-depth: 0 for the merge base to exist." >&2
    exit 1
  fi
  echo "check-palette-drift: base ref '$BASE_REF' not found; skipping (not CI)." >&2
  exit 0
fi

merge_base="$(git merge-base "$BASE_REF" HEAD)"

# Added lines only: the '+' side of the diff, minus the '+++' file headers.
added="$(git diff "$merge_base"...HEAD -- 'src/*.tsx' 'src/*.ts' 'src/*.css' \
  | grep -E '^\+' | grep -Ev '^\+\+\+' || true)"

if [[ -z "$added" ]]; then
  echo "check-palette-drift: no added source lines."
  exit 0
fi

# --- no accent stripes ---------------------------------------------------------
# Colour classes that are NOT neutral: semantic accents, severity, palette hexes.
STRIPE_COLOUR="(primary|secondary|accent|destructive|warning|info|success|ring|signal|sev-[a-z]+|severity-[a-z]+|${PALETTE}-[0-9]{2,3}|\\[#[0-9a-fA-F]+\\])"
stripe_lines="$(printf '%s\n' "$added" \
  | grep -v 'stripe-ok:' \
  | grep -v 'animate-spin' \
  | grep -E "\bborder-[ltse]-${STRIPE_COLOUR}(/[0-9]+)?\b|\bborder-[ltse]-[2-8]\b.*\bborder-${STRIPE_COLOUR}\b|\bborder-${STRIPE_COLOUR}\b.*\bborder-[ltse]-[2-8]\b" \
  | sed -E 's/^\+[[:space:]]*//' | cut -c1-160 || true)"
stripe_fail=0
if [[ -n "$stripe_lines" ]]; then
  stripe_fail=1
  cat >&2 <<EOF

This branch adds a coloured left/top border stripe on a card, tile or row:

$stripe_lines

No accent stripes (they read as generic AI styling). Show state with a small
status pill or dot plus text, an icon, or the value's own semantic colour, and
keep the card on a uniform 1px neutral border. A selected row is the raised
surface (bg-muted/40) plus a check or bold label. A neutral indent rule such as
\`border-l-2 border-muted\` is fine. If this really is not a card stripe, say so:

  className="border-l-4 border-primary" // stripe-ok: <reason>

EOF
fi

# --- priority and severity colours live in one place -----------------------------
# Priority (P0-P3) and severity (critical..info) each have one token set: the
# --prio-* / --sev-* tokens in src/styles/theme.css, read through
# src/lib/priority-colors.ts and src/lib/severity-colors.ts and rendered by
# <PriorityBadge> and <SeverityBadge>. Workflow status has the --st-* tokens, read
# through src/lib/status-colors.ts and rendered by <StatusLozenge>. Outside those modules an added line may
# not (1) name a --prio/--sev token or its Tailwind class, (2) colour a priority
# class with a palette class or hex, or (3) key a palette class or hex by a
# severity name. Annotate a real exception with `label-colour-ok: <reason>`.
LABEL_ALLOW='^(web/)?src/(lib/(priority-colors|severity-colors|status-colors|health-colors|tag-colors|chart-palette)[.]ts|components/ui/counter[.]tsx|styles/theme[.]css)$|(__tests__/|[.]test[.]tsx?$)'
LABEL_TOKEN='\b(bg|text|border|ring|fill|stroke|from|via|to|divide|outline|shadow)-(prio|sev|st|hl|ctr|tag)-[a-z0-9-]+|var\(--(prio|sev|st|hl|ctr|tag|viz-sev)-'
LABEL_COLOUR="(\\b${PROPS}-${PALETTE}-[0-9]{2,3}\\b|#[0-9a-fA-F]{6}\\b)"
label_lines="$(git diff --unified=0 "$merge_base"...HEAD -- 'src/*.tsx' 'src/*.ts' \
  | awk -v allow="$LABEL_ALLOW" '
      /^\+\+\+ /{ f=substr($0,7); skip=(f ~ allow); next }
      /^\+/ && !skip { sub(/^\+/,""); print f ": " $0 }' \
  | grep -v 'label-colour-ok:' \
  | grep -E "${LABEL_TOKEN}|(['\"]P[0-3]['\"]|\\bP[0-3]['\"]?[[:space:]]*:|[Pp]riority).*${LABEL_COLOUR}|\\b(critical|high|medium|low|info)['\"]?[[:space:]]*:.*${LABEL_COLOUR}" \
  | cut -c1-170 || true)"
label_fail=0
if [[ -n "$label_lines" ]]; then
  label_fail=1
  cat >&2 <<EOF

This branch hand-writes a priority or severity colour outside the shared module:

$label_lines

Priority and severity each have ONE colour source, so a P0 or a Critical looks the
same in a list, a chart and a drawer:
  priority  <PriorityBadge priorityClass="P1" />   src/lib/priority-colors.ts
  severity  <SeverityBadge severity="high" />      src/lib/severity-colors.ts
  status    <StatusLozenge tone="progress" />      src/lib/status-colors.ts
Charts take PRIORITY_CHART_COLORS / SEVERITY_CHART_COLORS. Teal is the act-here
accent and is never a priority or severity colour. If this really is neither,
say so on the line:  // label-colour-ok: <reason>

EOF
fi
stripe_fail=$((stripe_fail || label_fail))

# --- one label system (research/247) -------------------------------------------
# Labels come from the primitives in src/components/ui (HealthStatus,
# StatusLozenge, SignalChip, Tag, Counter, Marker, SeverityBadge, PriorityBadge).
# An ADDED line outside components/ui/, the colour modules and tests may not:
#   (a) put a colour class on a <Badge> (bg-/text-/border- + a semantic or palette colour);
#   (b) set 9-11px text on a badge, pill or rounded-full line;
#   (c) use uppercase or font-mono on a <Badge> line (mono is for ids, CVEs, versions);
#   (d) spin or pulse inside a status component (nothing spins or pulses);
#   (e) declare a new *_COLORS / *_BADGE_* map outside lib/*-colors.ts;
#   (f) put state text on its own tint (text-success on bg-success/10 fails AA);
#   (g) hand-pick a hex colour (bg-[#…], style={{ color: '#…' }}, fill="#…").
# Annotate a real exception with `label-ok: <reason>`.
# The generated brand artwork (src/assets/brand-data.generated.ts) is the logo's own SVG
# drawings as strings, so their fill colours are the brand, not styling.
SYS_ALLOW='^(web/)?src/(components/ui/|lib/[a-z-]*-colors[.]ts$|styles/|assets/brand-data[.]generated[.]ts$)|(__tests__/|[.]test[.]tsx?$)'
SEMANTIC='(primary|secondary|accent|destructive|warning|success|info|muted|foreground|background|card|signal|brand|sev-[a-z]+|st-[a-z]+-[a-z]+|hl-[a-z]+|prio-[0-9])'
BADGE_COLOUR="\\b(bg|text|border|ring)-(${SEMANTIC}|${PALETTE}-[0-9]{2,3})\\b"
TAB="$(printf '\t')"
sys_all="$(git diff --unified=0 "$merge_base"...HEAD -- 'src/*.tsx' 'src/*.ts' \
  | awk -v allow="$SYS_ALLOW" '
      /^\+\+\+ /{ f=substr($0,7); skip=(f ~ allow); next }
      /^\+/ && !skip { sub(/^\+/,""); print f "\t" $0 }' \
  | grep -v 'label-ok:' || true)"
sys_lines=""
if [[ -n "$sys_all" ]]; then
  a_lines="$(printf '%s\n' "$sys_all" | grep -E '<Badge\b' | grep -E "$BADGE_COLOUR" | sed 's/^/(a) colour class on Badge: /' || true)"
  b_lines="$(printf '%s\n' "$sys_all" | grep -E 'Badge|rounded-full|Pill' | grep -E 'text-\[(9|10|11)(px|\.[0-9]+px)\]' | sed 's/^/(b) text under 12px on a label: /' || true)"
  c_lines="$(printf '%s\n' "$sys_all" | grep -E '<Badge\b' | grep -E '\buppercase\b|\bfont-mono\b' | sed 's/^/(c) uppercase or mono on a label: /' || true)"
  d_lines="$(printf '%s\n' "$sys_all" | grep -iE '(status|health|pill|chip|badge|lozenge)' | grep -E 'animate-(spin|ping|pulse)|<Loader2' | sed 's/^/(d) spinning or pulsing status: /' || true)"
  e_lines="$(printf '%s\n' "$sys_all" | grep -E "${TAB}[[:space:]]*(export )?const [A-Z0-9_]*(_COLORS|_BADGE_[A-Z_]*)\b" | sed 's/^/(e) new colour map: /' || true)"
  # (f) state text on its own tint: text-success on bg-success/10 is 4.38:1 in light mode (below AA).
  f_lines="$(printf '%s\n' "$sys_all" | grep -E '\bbg-(success|warning|destructive|info)/[0-9]+' | grep -E '\btext-(success|warning|destructive|info)\b' | sed 's/^/(f) state text on its own tint: /' || true)"
  # (g) a hand-picked hex colour (arbitrary class or inline style / SVG attribute).
  g_lines="$(printf '%s\n' "$sys_all" | grep -E "\b(bg|text|border|fill|stroke|ring|outline|from|to|via)-\[#[0-9a-fA-F]{3,8}\]|\b(color|background|backgroundColor|fill|stroke|borderColor)[[:space:]]*[:=][[:space:]]*[{]?['\"]#[0-9a-fA-F]{3,8}['\"]" | sed 's/^/(g) hand-picked hex colour: /' || true)"
  sys_lines="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n' "$a_lines" "$b_lines" "$c_lines" "$d_lines" "$e_lines" "$f_lines" "$g_lines" | grep -v '^$' | tr '\t' ' ' | cut -c1-190 || true)"
fi
sys_fail=0
if [[ -n "$sys_lines" ]]; then
  sys_fail=1
  cat >&2 <<EOF

This branch hand-styles a label outside the label primitives:

$sys_lines

One label system: pick the primitive by meaning (src/components/ui).
  a number            <Counter>          a feature marker   <Marker>
  how bad             <SeverityBadge>    the decision       <PriorityBadge>
  a work item's state <StatusLozenge>    a machine's state  <HealthStatus>
  a supporting fact   <SignalChip>       a classification   <Tag>
Labels are 12px or more, sentence case, sans (mono only for ids, CVEs and
versions), and never spin or pulse. Colours live in lib/*-colors.ts and
theme.css; charts take seriesVar / seriesFill from lib/chart-palette.ts. State
text never sits on its own tint (below AA), and no colour is a hand-picked hex
(research/257 measures every family). If this really is none of those, say so on the line:
  // label-ok: <reason>

EOF
fi
stripe_fail=$((stripe_fail || sys_fail))

violations="$(printf '%s\n' "$added" \
  | grep -v 'palette-ok:' \
  | grep -oE "\b${PROPS}-${PALETTE}-[0-9]{2,3}\b" \
  | sort | uniq -c | sort -rn || true)"

if [[ -z "$violations" ]]; then
  echo "check-palette-drift: no new hardcoded palette classes."
  exit "$stripe_fail"
fi

count="$(printf '%s\n' "$violations" | awk '{s+=$1} END{print s+0}')"

cat >&2 <<EOF

This branch adds $count hardcoded Tailwind palette class(es):

$violations

Prefer a semantic token from src/styles/theme.css — those carry their own
dark-mode value, a literal palette class does not:

  text-gray-500    ->  text-muted-foreground
  bg-white         ->  bg-background   (bg-card inside a Card)
  border-gray-200  ->  border-border
  text-gray-900    ->  text-foreground

For severity colours, import from src/lib/severity-colors.ts rather than writing
red / orange / yellow by hand. It already exports every variant in use:
SEVERITY_CHART_COLORS (hex, for charts), SEVERITY_BADGE_SOFT, SEVERITY_BADGE_SOLID,
SEVERITY_TEXT_COLORS, SEVERITY_DOT_COLORS, SEVERITY_BORDER_COLORS.

If a token genuinely does not fit — a brand colour, a third-party embed, a set of
distinct accents — say so on the line and this gate will allow it:

  color: 'bg-amber-500/10 text-amber-500', // palette-ok: distinct card accent

EOF
exit 1
