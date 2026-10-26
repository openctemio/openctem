/**
 * Internal design references (RFC numbers, research notes, decision and
 * question ids) must never reach a person using the product. This walks the
 * i18n dictionaries (every value) and the non-test source under src/ and
 * console/src (string and template literals; comments are skipped) and fails
 * on those patterns. Comments, tests and docs/rfcs may keep the references.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const WEB = join(__dirname, '..', '..', '..', '..')

const INTERNAL_REF =
  /RFC-\d+|research\/\d+|\((?:Q|D)\d+\b[^)]*\)|\bQ\d+ \([a-z]\)|[Oo]wner decision|phase P\d/

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.next' || name === '__tests__' || name === 'dist')
      continue
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

function strings(obj: unknown, path: string, out: [string, string][]) {
  if (typeof obj === 'string') out.push([path, obj])
  else if (obj && typeof obj === 'object')
    for (const [k, v] of Object.entries(obj)) strings(v, `${path}.${k}`, out)
}

/** Drops whole-line comments and trailing `// ...` comments. */
function codeOnly(line: string): string {
  const t = line.trim()
  if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('{/*'))
    return ''
  return line.replace(/\s\/\/\s.*$/, '').replace(/\/\*.*?\*\//g, '')
}

describe('no internal references in user-facing text', () => {
  it('the pattern matches what it should and nothing else', () => {
    for (const s of [
      '(RFC-040 P2)',
      'see research/134',
      '(D7)',
      '(Q4 (a))',
      'owner decision',
      'phase P0',
    ])
      expect(INTERNAL_REF.test(s), s).toBe(true)
    for (const s of ['RFC3339', 'RFC 7644', 'Q&A', 'RFC 9110 requires'])
      expect(INTERNAL_REF.test(s), s).toBe(false)
  })

  it('i18n dictionaries carry none', () => {
    const dir = join(WEB, 'src', 'lib', 'i18n', 'dictionaries')
    const bad: string[] = []
    for (const f of walk(dir).filter((p) => p.endsWith('.json'))) {
      const all: [string, string][] = []
      strings(JSON.parse(readFileSync(f, 'utf8')), '', all)
      for (const [k, v] of all)
        if (INTERNAL_REF.test(v)) bad.push(`${relative(WEB, f)}${k}: ${v.slice(0, 80)}`)
    }
    expect(bad, bad.join('\n')).toEqual([])
  })

  it('source strings carry none', () => {
    const bad: string[] = []
    for (const root of [join(WEB, 'src'), join(WEB, 'console', 'src')]) {
      for (const f of walk(root).filter(
        (p) => /\.(ts|tsx)$/.test(p) && !/\.(test|spec)\./.test(p)
      )) {
        readFileSync(f, 'utf8')
          .split('\n')
          .forEach((line, i) => {
            if (INTERNAL_REF.test(codeOnly(line)))
              bad.push(`${relative(WEB, f)}:${i + 1}: ${line.trim().slice(0, 100)}`)
          })
      }
    }
    expect(bad, bad.join('\n')).toEqual([])
  })
})
