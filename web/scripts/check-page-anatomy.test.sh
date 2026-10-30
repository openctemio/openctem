#!/bin/sh
# sh web/scripts/check-page-anatomy.test.sh
# Runs the page-anatomy gate against a throwaway repo.
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
fail=0
git -C "$t" init -q -b develop
git -C "$t" config user.email t@example.invalid
git -C "$t" config user.name t
mkdir -p "$t/src/features/x" "$t/src/features/shared/components" "$t/src/app/x"
echo 'export const p = 1' > "$t/src/app/x/page.tsx"
echo 'export const a = 1' > "$t/src/features/x/a.tsx"
echo 'export const b = 1' > "$t/src/features/shared/components/metric-strip.tsx"
git -C "$t" add -A
git -C "$t" commit -q -m base
git -C "$t" checkout -q -b change

run() { # <file> <added line> -> exit code of the gate
  printf '%s\n' "$2" > "$t/src/$1"
  git -C "$t" commit -q -am x
  (cd "$t" && bash "$here/check-page-anatomy.sh" develop >/dev/null 2>&1)
  rc=$?
  git -C "$t" reset -q --hard develop
  return $rc
}
must_fail() { run features/x/a.tsx "$2" && { echo "FAIL accepted: $1"; fail=1; }; }
must_pass() { run "${3:-features/x/a.tsx}" "$2" || { echo "FAIL rejected: $1"; fail=1; }; }

must_fail 'new StatsCard' '<StatsCard title="Open" value={3} icon={Shield} />'
must_fail 'ad-hoc tile' '<div className="text-2xl font-bold">{count}</div>'
must_fail 'arbitrary size' '<span className="text-[10px] uppercase">x</span>'
must_fail 'arbitrary rem size' '<span className="text-[0.8rem]">x</span>'
must_fail 'mixed sizes on one line' '<span className="text-xs">First seen</span> <span className="text-sm">{t}</span>'
must_fail 'margin on route tabs' '<GatedSectionTabs tabs={T} className="mt-4 mb-0" />'
must_fail 'segmented lens as a filter' '<SegmentedLens label="Status" value={s} options={o} onChange={set} />'
must_fail 'tab icon with classes' '<TabsTrigger value="a"><Shield className="h-4 w-4 text-red-500" />A</TabsTrigger>'
must_fail 'tab icon with classes on the next line' "$(printf '<TabsTrigger value="a">\n  <Shield className="size-4" />')"
must_fail 'second tab row' "$(printf '<SectionTabs tabs={T} />\n<TabsList>')"
must_fail 'page header without a stack' '<PageHeader title="X" />'
must_pass 'page header in a stack' "$(printf '<PageStack>\n<PageHeader title="X" />')"
must_pass 'plain tab trigger' "$(printf '<TabsTrigger value="a">\n  {t(\x27a\x27)}')"
must_fail_at() { run "$1" "$2" && { echo "FAIL accepted: $3"; fail=1; }; }
must_fail_at app/x/page.tsx "$(printf 'export default function P() {\n  const { t } = useTranslation()\n}')" 'server page with hooks'
must_pass 'client page with hooks' "$(printf '/** doc */\n\047use client\047\nexport default function P() {\n  const [a] = useState(1)\n}')" app/x/page.tsx
must_pass 'metric strip owns its number' '<span className="text-2xl font-semibold">' features/shared/components/metric-strip.tsx
must_pass 'responsive size' '<p className="text-sm sm:text-base">x</p>'
must_pass 'one size' '<span className="text-xs text-muted-foreground">Source</span>'
must_pass 'annotated exception' '<span className="text-[10px]">x</span> {/* anatomy-ok: chart axis */}'
must_pass 'tabs without margin' '<GatedSectionTabs tabs={T} label={l} />'

find "$t" -delete
[ $fail = 0 ] && echo ok
exit $fail
