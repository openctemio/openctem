#!/bin/sh
# sh web/scripts/check-palette-drift.test.sh
# Runs the drift gate against a throwaway repo and checks the accent-stripe rule.
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
fail=0
git -C "$t" init -q -b develop
git -C "$t" config user.email t@example.invalid
git -C "$t" config user.name t
mkdir -p "$t/src"
echo 'export const a = 1' > "$t/src/a.tsx"
git -C "$t" add -A
git -C "$t" commit -q -m base
git -C "$t" checkout -q -b change

run() { # <added line> -> exit code of the gate
  printf '%s\n' "$1" > "$t/src/a.tsx"
  git -C "$t" commit -q -am x
  (cd "$t" && bash "$here/check-palette-drift.sh" develop >/dev/null 2>&1)
  rc=$?
  git -C "$t" reset -q --hard develop
  return $rc
}
must_fail() { run "$2" && { echo "FAIL accepted: $1"; fail=1; }; }
must_pass() { run "$2" || { echo "FAIL rejected: $1"; fail=1; }; }

must_fail 'left stripe, width + colour' '<div className="rounded border border-l-4 border-l-primary">x</div>'
must_fail 'colour only on one side' "card: 'border-l-warning',"
must_fail 'top stripe' '<div className="border-t-2 border-t-destructive" />'
must_fail 'width plus all-sides colour' '<div className="border-l-4 border-primary" />'
must_fail 'logical start stripe' "own && 'border-s-2 border-s-primary bg-primary/5'"
must_pass 'neutral indent' '<div className="space-y-2 border-l-2 border-muted ps-3">'
must_pass 'spinner' '<span className="animate-spin border-2 border-t-primary" />'
must_pass 'annotated exception' '<div className="border-l-4 border-l-primary" /> {/* stripe-ok: wizard step rail */}'
must_pass 'plain card' '<div className="rounded border bg-card p-4" />'

# priority / severity colours (the file is src/a.tsx, outside the shared modules)
must_fail 'priority colour by hand' "const P1 = 'P1' // bg-orange-500"
must_fail 'priority hex' "const pc = { P0: '#ff0000' }"
must_fail 'severity map by palette' "critical: 'bg-red-500/10 text-red-500',"
must_fail 'severity hex' "high: '#f97316',"
must_fail 'sev token class by hand' '<span className="bg-sev-high/10" />'
must_fail 'prio token var by hand' "fill: 'var(--prio-0)'"
must_fail 'status token class by hand' '<span className="bg-st-progress-bg" />'
must_fail 'status token var by hand' "fill: 'var(--st-open-fg)'"
must_pass 'shared lozenge use' '<StatusLozenge tone="open" label="x" />'
must_pass 'shared badge use' '<PriorityBadge priorityClass="P1" />'
must_pass 'annotated colour exception' "critical: '#ff0000', // label-colour-ok: exported PDF palette"

# one label system: no hand-styled labels (colour on Badge, tiny text, uppercase / mono, spin, new maps)
must_fail 'semantic colour on Badge' '<Badge variant="outline" className="bg-success/10 text-success">x</Badge>'
must_fail 'border colour on Badge' '<Badge className="border-warning">x</Badge>'
must_fail 'tiny text on a pill' '<span className="rounded-full px-2 text-[10px]">x</span>'
must_fail 'tiny text on Badge' '<Badge className="text-[11px]">x</Badge>'
must_fail 'uppercase Badge' '<Badge className="uppercase">{row.source}</Badge>'
must_fail 'mono Badge' '<Badge className="font-mono">{row.name}</Badge>'
must_fail 'spinning status' '<Loader2 className="size-3 animate-spin" /> {statusLabel}'
must_fail 'spinning health badge' '<RunBadge className="animate-spin" />'
must_fail 'new colour map' 'const FOO_STATUS_COLORS = { a: "x" }'
must_fail 'new badge map' 'export const FOO_BADGE_CLASS = {}'
must_pass 'Badge without colour' '<Badge variant="outline">{count}</Badge>'
must_pass 'plain 12px text on a pill' '<span className="rounded-full px-2 text-xs">x</span>'
must_pass 'spinner on a button' '<Loader2 className="size-4 animate-spin" />'
must_pass 'label primitive' '<HealthStatus state="ok" label="Online" />'
must_pass 'annotated label exception' '<Badge className="font-mono">{id}</Badge> {/* label-ok: a commit id */}'

find "$t" -delete
[ $fail = 0 ] && echo ok
exit $fail
