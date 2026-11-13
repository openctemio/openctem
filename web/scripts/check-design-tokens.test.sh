#!/bin/sh
# sh web/scripts/check-design-tokens.test.sh
# Runs the design-token gate against a throwaway repo.
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
fail=0
git -C "$t" init -q -b develop
git -C "$t" config user.email t@example.invalid
git -C "$t" config user.name t
mkdir -p "$t/src/features/x" "$t/src/components/ui" "$t/src/components/layout" "$t/src/styles" \
  "$t/src/features/x/__tests__" "$t/console/src/features/admin-console/components"
for f in features/x/a.tsx components/ui/button.tsx components/layout/a.tsx styles/theme.css \
  features/x/__tests__/a.test.tsx features/x/a.css; do
  echo '/* base */' > "$t/src/$f"
done
echo '/* base */' > "$t/console/src/features/admin-console/components/a.tsx"
git -C "$t" add -A
git -C "$t" commit -q -m base
git -C "$t" checkout -q -b change

run() { # <file under src/ or ../console/src> <added line> -> exit code of the gate
  printf '%s\n' "$2" >> "$t/src/$1"
  git -C "$t" commit -q -am x
  (cd "$t" && bash "$here/check-design-tokens.sh" develop >/dev/null 2>&1)
  rc=$?
  git -C "$t" reset -q --hard develop
  return $rc
}
must_fail() { run "${3:-features/x/a.tsx}" "$2" && { echo "FAIL accepted: $1"; fail=1; }; }
must_pass() { run "${3:-features/x/a.tsx}" "$2" || { echo "FAIL rejected: $1"; fail=1; }; }

must_fail 'hex in a class' '<div className="bg-[#0a1628]" />'
must_fail 'short hex in a class' '<div className="text-[#fff]" />'
must_fail 'hex in a style' '<div style={{ color: "#0f766e" }} />'
must_fail 'rgb()' '<div style={{ background: "rgb(10 22 40 / 0.4)" }} />'
must_fail 'hsl() in css' '.x { color: hsl(200 10% 20%); }' features/x/a.css
must_fail 'oklch()' 'const c = "oklch(0.6 0.1 200)"'
must_fail 'arbitrary radius' '<div className="rounded-[10px]" />'
must_fail 'arbitrary side radius' '<div className="rounded-t-[6px]" />'
must_fail 'arbitrary shadow' '<div className="shadow-[0_1px_2px_black]" />'
must_fail 'arbitrary line height' '<p className="leading-[22px]" />'
must_fail 'arbitrary weight' '<p className="font-[650]" />'
must_fail 'font-bold' '<b className="font-bold">x</b>'
must_fail 'font-extrabold' '<b className="font-extrabold">x</b>'
must_fail 'height on a Button' '<Button className="h-7 px-2">x</Button>'
must_fail 'size on an icon Button' '<Button size="icon" className="size-11">x</Button>'
must_fail 'height on an Input' '<Input className="h-11" />'
must_fail 'min-height on a SelectTrigger' '<SelectTrigger className="min-h-[40px] w-40">'
must_fail 'raw text size in a migrated dir' '<span className="text-sm">x</span>' components/layout/a.tsx
must_fail 'responsive raw size in a migrated dir' '<span className="md:text-base">x</span>' components/layout/a.tsx
must_fail 'console migrated dir' '<span className="text-xs">x</span>' ../console/src/features/admin-console/components/a.tsx
must_pass 'role in a migrated dir' '<span className="text-dense text-muted-foreground">x</span>' components/layout/a.tsx
must_pass 'raw size outside the migrated dirs' '<span className="text-sm">x</span>'
must_pass 'kit file sets its own heights' 'size: { default: "h-control px-3" },' components/ui/button.tsx
must_pass 'width on a Button' '<Button className="w-full">x</Button>'
must_pass 'semantic token' '<div className="bg-card text-muted-foreground border-strong rounded-lg shadow-overlay" />'
must_pass 'anchor href' '<a href="#add">x</a>'
must_pass 'colour in the token file' '--x: #0a1628;' styles/theme.css
must_pass 'colour in a test' 'expect(x).toBe("#0a1628")' features/x/__tests__/a.test.tsx
must_pass 'font-semibold' '<b className="font-semibold">x</b>'
must_pass 'annotated exception' '<div className="bg-[#000]" /> {/* design-ok: third-party embed */}'

find "$t" -delete
[ $fail = 0 ] && echo ok
