/**
 * Guard: a catalog string with a `{name}` placeholder shows the braces to the
 * reader when its t() call passes no value for it ("Imports choose it as
 * format {format}."). Every `t('literal.key', ...)` call in src is checked
 * against the English and Vietnamese strings of its key: each placeholder
 * must be a variable the call passes. A call whose variables are not an
 * object literal (a variable, a spread) cannot be read statically and is
 * skipped; the brand variables are always filled by the provider. A string
 * filled by `.replace('{name}', ...)` or cut by `.split('{name}')` right after
 * the call counts as filled.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const SRC = join(process.cwd(), 'src')
const DICT = join(SRC, 'lib', 'i18n', 'dictionaries')
const ALWAYS_FILLED = new Set(['product', 'productShort'])
/** Strings that show braces on purpose: they teach the template syntax. */
const LITERAL_BRACES = new Set(['importMappings.transform.noVars'])

function catalog(lang: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const f of readdirSync(join(DICT, lang)).filter((n) => n.endsWith('.json'))) {
    Object.assign(out, JSON.parse(readFileSync(join(DICT, lang, f), 'utf8')))
  }
  return out
}

const PLURAL_BLOCK = /\{(\w+),\s*plural,(?:\s*(?:=\d+|\w+)\s*\{[^{}]*\})+\s*\}/g

/** `{name}` and the selector of `{name, plural, ...}`; text inside plural branches is not a variable. */
export function placeholders(str: string): Set<string> {
  const names = new Set<string>()
  const flat = str.replace(PLURAL_BLOCK, (_, name: string) => `{${name}}`)
  for (const m of flat.matchAll(/\{(\w+)\}/g)) names.add(m[1])
  return names
}

/**
 * The call whose arguments start at `open` (just after its opening
 * parenthesis): its top-level arguments and the index after its closing
 * parenthesis. Strings, template literals and nested brackets are skipped.
 */
function callAt(src: string, open: number): { args: string[]; end: number } | null {
  const args: string[] = []
  let depth = 0
  let start = open
  for (let i = open; i < src.length; i++) {
    const c = src[i]
    if (c === "'" || c === '"' || c === '`') {
      const q = c
      for (i++; i < src.length && src[i] !== q; i++) {
        if (src[i] === '\\') i++
        else if (q === '`' && src[i] === '$' && src[i + 1] === '{') {
          // a template expression: skip to its closing brace
          let d = 0
          for (i++; i < src.length; i++) {
            if (src[i] === '{') d++
            else if (src[i] === '}' && --d === 0) break
          }
        }
      }
      continue
    }
    if (c === '(' || c === '[' || c === '{') depth++
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) {
        if (c !== ')') return null
        args.push(src.slice(start, i).trim())
        return { args: args.filter((a, idx) => a !== '' || idx < args.length - 1), end: i + 1 }
      }
      depth--
    } else if (c === ',' && depth === 0) {
      args.push(src.slice(start, i).trim())
      start = i + 1
    }
  }
  return null
}

/** The variable names an object literal passes, or null when it cannot be read (a spread, not a literal). */
function literalKeys(arg: string): Set<string> | null {
  const body = arg.trim()
  if (!body.startsWith('{') || !body.endsWith('}')) return null
  const inner = body.slice(1, -1)
  if (inner.includes('...')) return null
  const parts = callAt(inner + ')', 0)?.args ?? []
  const keys = new Set<string>()
  for (const p of parts) {
    const m = p.match(/^['"]?([A-Za-z_$][\w$]*)['"]?\s*(?::|$)/)
    if (!m) return null
    keys.add(m[1])
  }
  return keys
}

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name)
    if (e.isDirectory()) {
      if (e.name !== '__tests__' && e.name !== 'node_modules') sourceFiles(full, out)
    } else if (/\.tsx?$/.test(e.name) && !/\.(test|spec)\.tsx?$/.test(e.name)) out.push(full)
  }
  return out
}

const CHAINED_FILL = /^\s*\.(?:replace|split)\(\s*['"]\{(\w+)\}['"]/

/** The unfilled placeholders of every t() call in one file. */
function unfilled(
  src: string,
  catalogs: Record<string, string>[]
): { key: string; missing: string[] }[] {
  const out: { key: string; missing: string[] }[] = []
  const tCall = /(?<![\w$.])t\(\s*(['"])([\w.\-]+)\1/g
  for (const m of src.matchAll(tCall)) {
    const key = m[2]
    if (LITERAL_BRACES.has(key)) continue
    const strings = catalogs.map((c) => c[key]).filter((s): s is string => s !== undefined)
    if (strings.length === 0) continue
    const call = callAt(src, (m.index ?? 0) + m[0].indexOf('(') + 1)
    if (!call) continue
    const { args } = call
    let passed = new Set<string>()
    if (args.length >= 3) {
      const keys = literalKeys(args[2])
      if (!keys) continue
      passed = keys
    } else if (args.length === 2 && args[1].startsWith('{')) {
      // t(key, { vars }) with no fallback
      const keys = literalKeys(args[1])
      if (!keys) continue
      passed = keys
    }
    for (let rest = src.slice(call.end); ;) {
      const c = rest.match(CHAINED_FILL)
      if (!c) break
      passed.add(c[1])
      const next = callAt(rest, c[0].indexOf('(') + 1)
      if (!next) break
      rest = rest.slice(next.end)
    }
    const missing = new Set<string>()
    for (const s of strings)
      for (const name of placeholders(s))
        if (!passed.has(name) && !ALWAYS_FILLED.has(name)) missing.add(name)
    if (missing.size) out.push({ key, missing: [...missing].sort() })
  }
  return out
}

describe('t() placeholders', () => {
  it('reads a call and its variables', () => {
    const cat = [{ a: 'Hello {name}', b: '{count, plural, one {# x} other {# xs}} for {who}' }]
    expect(unfilled(`t('a', 'Hello')`, cat)).toEqual([{ key: 'a', missing: ['name'] }])
    expect(unfilled(`t('a', 'Hello {name}', { name })`, cat)).toEqual([])
    expect(unfilled(`t('a', \`x \${y}\`, { name: f(a, b) })`, cat)).toEqual([])
    expect(unfilled(`t('a', 'x', vars)`, cat)).toEqual([])
    expect(unfilled(`t('b', 'x', { count: 2 })`, cat)).toEqual([{ key: 'b', missing: ['who'] }])
    expect(unfilled(`format(t('a'))`, cat)).toEqual([{ key: 'a', missing: ['name'] }])
    expect(unfilled(`obj.t('a')`, cat)).toEqual([])
    expect(unfilled(`t('a', 'Hello {name}').replace('{name}', n)`, cat)).toEqual([])
    expect(unfilled(`t('b', 'x').replace('{who}', w)`, cat)).toEqual([
      { key: 'b', missing: ['count'] },
    ])
  })

  it('reads plural branches as text, not variables', () => {
    expect([...placeholders('{n} {count, plural, one {needs} other {need}} {name}')]).toEqual([
      'n',
      'count',
      'name',
    ])
  })

  it('every t() call fills each placeholder of its English and Vietnamese strings', () => {
    const catalogs = [catalog('en'), catalog('vi')]
    const bad: string[] = []
    for (const file of sourceFiles(SRC)) {
      const src = readFileSync(file, 'utf8')
      if (!src.includes('t(')) continue
      for (const u of unfilled(src, catalogs))
        bad.push(`${file.slice(SRC.length + 1)}: ${u.key} {${u.missing.join('}, {')}}`)
    }
    expect(bad).toEqual([])
  })
})
