#!/bin/sh
# sh web/scripts/check-separators.test.sh
# Runs the separator gate against a throwaway repo.
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
fail=0
git -C "$t" init -q -b develop
git -C "$t" config user.email t@example.invalid
git -C "$t" config user.name t
mkdir -p "$t/src/lib/i18n/dictionaries/en" "$t/src/__tests__"
echo 'export const a = 1' > "$t/src/a.tsx"
echo '{}' > "$t/src/lib/i18n/dictionaries/en/x.json"
echo 'export const a = 1' > "$t/src/__tests__/a.tsx"
git -C "$t" add -A
git -C "$t" commit -q -m base
git -C "$t" checkout -q -b change

run() { # <file> <added line> -> exit code of the gate
  printf '%s\n' "$2" > "$t/$1"
  git -C "$t" commit -q -am x
  (cd "$t" && bash "$here/check-separators.sh" develop >/dev/null 2>&1)
  rc=$?
  git -C "$t" reset -q --hard develop
  return $rc
}
must_fail() { run "$2" "$3" && { echo "FAIL accepted: $1"; fail=1; }; }
must_pass() { run "$2" "$3" || { echo "FAIL rejected: $1"; fail=1; }; }

A=src/a.tsx
D=src/lib/i18n/dictionaries/en/x.json

must_fail 'middle dot text' $A '<span>{a} · {b}</span>'
must_fail 'middle dot string' $A "const s = a + ' · ' + b"
must_fail 'bullet separator' $A '<span>{a} • {b}</span>'
must_fail 'dot operator' $A "const s = 'a ∙ b'"
must_fail 'dot operator two' $A "const s = 'a ⋅ b'"
must_fail 'dictionary dot' $D '  "a.b": "{size} · updated {date}",'
must_fail 'join dot' $A "const s = parts.join(' · ')"
must_fail 'join em dash' $A "const s = parts.join(' — ')"
must_fail 'join pipe' $A 'const s = parts.join(" | ")'
must_fail 'join template' $A 'const s = parts.join(` | `)'
must_fail 'dictionary em dash' $D '  "a.b": "Immediate — actively exploited",'
must_fail 'code em dash' $A "const s = \`\${p.key} — \${p.name}\`"
must_fail 'jsx em dash' $A '<span>{p.key} — {p.name}</span>'
must_fail 'template pipe' $A 'const s = `${a} | ${b}`'
must_fail 'jsx pipe' $A '<span>{a}</span>|<span>{b}</span>'
must_pass 'empty cell placeholder' $A "return value ?? '—'"
must_pass 'jsx placeholder' $A '<td>—</td>'
must_pass 'dictionary placeholder' $D '  "a.empty": "—",'
must_pass 'credential mask' $A "const mask = '••••••••'"
must_pass 'type union' $A "type A = 'a' | 'b' | { c: 1 } | { d: 2 }"
must_pass 'comment with em dash' $A '// the old label — kept for the audit trail'
must_pass 'block comment with dot' $A ' * a · b is replaced by MetaLine'
must_pass 'trailing comment' $A "const a = 1 // was a · b"
must_pass 'annotated exception' $A "const s = '·' // separator-ok: fixture asserting absence"
must_pass 'comma list' $A "const s = parts.join(', ')"
must_pass 'colon label' $D '  "a.b": "Immediate: actively exploited",'
must_pass 'test file' src/__tests__/a.tsx "expect(text).toBe('a · b')"

find "$t" -delete
[ $fail = 0 ] && echo ok
exit $fail
