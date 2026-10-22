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
must_pass 'neutral indent' '<div className="space-y-2 border-l-2 border-muted ps-3">'
must_pass 'spinner' '<span className="animate-spin border-2 border-t-primary" />'
must_pass 'annotated exception' '<div className="border-l-4 border-l-primary" /> {/* stripe-ok: wizard step rail */}'
must_pass 'plain card' '<div className="rounded border bg-card p-4" />'

find "$t" -delete
[ $fail = 0 ] && echo ok
exit $fail
