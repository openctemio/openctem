/**
 * A content-sized table (`columnSizing="content"`, column-sizing.ts) takes
 * its widths from its content: a column declares its kind, never px. An
 * override (`width`, `minWidth`, `maxWidth` in a column's meta) is allowed
 * only with its reason beside it (`sizeReason: '...'`), and `hideBelow` (px
 * points that came from fixed widths) gives way to `dropOrder`.
 *
 * Checked in every file that renders a content-sized DataTable and defines
 * its columns there.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const WEB = join(__dirname, '..', '..', '..', '..', '..', '..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console', 'src')].filter((d) => existsSync(d))
const SKIP_DIR = new Set(['__tests__', '__mocks__', 'generated', 'dictionaries', 'node_modules'])

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return SKIP_DIR.has(name) ? [] : sources(path)
    if (/\.(test|spec|stories)\.tsx?$/.test(name) || name.endsWith('.d.ts')) return []
    return /\.tsx?$/.test(name) ? [path] : []
  })
}

/** The `meta: { ... }` object literals of a file (balanced braces). */
export function metaObjects(text: string): string[] {
  const out: string[] = []
  for (const m of text.matchAll(/\bmeta:\s*\{/g)) {
    let depth = 0
    const start = m.index + m[0].length - 1
    for (let i = start; i < text.length; i++) {
      if (text[i] === '{') depth++
      else if (text[i] === '}' && --depth === 0) {
        out.push(text.slice(start, i + 1))
        break
      }
    }
  }
  return out
}

/** Problems of one file's column metas. */
export function overrideProblems(text: string): string[] {
  const problems: string[] = []
  for (const meta of metaObjects(text)) {
    const head = meta.replace(/\s+/g, ' ').slice(0, 80)
    if (/\b(width|minWidth|maxWidth):/.test(meta) && !/\bsizeReason:/.test(meta)) {
      problems.push(`width override without sizeReason: ${head}`)
    }
    if (/\bhideBelow:/.test(meta)) problems.push(`hideBelow on a content-sized table: ${head}`)
  }
  return problems
}

describe('content-sized tables declare kinds, not px', () => {
  it('detects an override without its reason (self-test)', () => {
    expect(overrideProblems(`meta: { kind: 'text', width: 120, label: 'x' }`)).toHaveLength(1)
    expect(
      overrideProblems(`meta: { kind: 'text', width: 120, sizeReason: 'fixed chip', label: 'x' }`)
    ).toHaveLength(0)
    expect(overrideProblems(`meta: { kind: 'severity', hideBelow: 900 }`)).toHaveLength(1)
    expect(overrideProblems(`meta: { kind: 'severity', dropOrder: 1 }`)).toHaveLength(0)
  })

  it('every content-sized table file passes', () => {
    const bad: string[] = []
    const files = ROOTS.flatMap(sources).filter((f) =>
      readFileSync(f, 'utf8').includes('columnSizing="content"')
    )
    expect(files.length).toBeGreaterThan(0)
    for (const f of files) {
      for (const p of overrideProblems(readFileSync(f, 'utf8')))
        bad.push(`${relative(WEB, f)}: ${p}`)
    }
    expect(bad).toEqual([])
  })
})
