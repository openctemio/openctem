/**
 * Every user-visible string goes through `t()` with an English and a
 * Vietnamese value (owner rule). The console still has text written straight
 * into components; this ratchet keeps that count from growing and makes it
 * shrink:
 *
 * - a file that is not in literal-ui-text-debt.json may add no literal text;
 * - a listed file may not go above its count;
 * - a listed file that went below its count must lower it, so the gain is
 *   kept (regenerate with UPDATE_LITERAL_DEBT=1, see below).
 *
 * What counts is decided by literal-ui-text.ts: JSX text, text attributes
 * (title, aria-label, placeholder...), strings shown through JSX expressions,
 * label-like object properties in components, and toast messages (also in
 * hooks and other .ts files). Escape hatch for a real exception: an
 * `i18n-ok: <reason>` comment on the line or the line above.
 *
 * Regenerate the baseline after a clean-up (counts may only go down; the
 * diff is reviewed):
 *   UPDATE_LITERAL_DEBT=1 npx vitest run src/lib/__tests__/literal-ui-text-ratchet.test.ts
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import { findLiteralUiText, type LiteralFinding } from './literal-ui-text'
import debt from './literal-ui-text-debt.json'

const SRC = join(__dirname, '..', '..')
const DEBT_FILE = join(__dirname, 'literal-ui-text-debt.json')

// Catalogs, generated wire types and tests are not screen text.
const SKIP_DIR = new Set(['__tests__', '__mocks__', 'generated', 'dictionaries'])

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return SKIP_DIR.has(name) ? [] : sources(path)
    if (/\.(test|spec|stories)\.tsx?$/.test(name) || name.endsWith('.d.ts')) return []
    return /\.tsx?$/.test(name) ? [path] : []
  })
}

/** Findings per file: every kind in components, toasts only in plain .ts. */
function census(): Map<string, LiteralFinding[]> {
  const out = new Map<string, LiteralFinding[]>()
  for (const file of sources(SRC)) {
    const all = findLiteralUiText(file, readFileSync(file, 'utf8'))
    const hits = file.endsWith('.tsx') ? all : all.filter((f) => f.kind === 'toast')
    if (hits.length) out.set(relative(SRC, file), hits)
  }
  return out
}

const baseline = debt as Record<string, number>

describe('literal UI text ratchet', () => {
  const found = census()

  if (process.env.UPDATE_LITERAL_DEBT === '1') {
    it('writes the baseline', () => {
      const next = Object.fromEntries(
        [...found.entries()]
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([file, hits]) => [file, hits.length])
      )
      writeFileSync(DEBT_FILE, JSON.stringify(next, null, 2) + '\n')
    })
    return
  }

  it('adds no literal UI text (use t() with en and vi values)', () => {
    const grown = [...found.entries()]
      .filter(([file, hits]) => hits.length > (baseline[file] ?? 0))
      .map(
        ([file, hits]) =>
          `${file}: ${hits.length} (allowed ${baseline[file] ?? 0})\n` +
          hits.map((h) => `  ${h.line} ${h.kind}: ${h.text}`).join('\n')
      )
    expect(grown, grown.join('\n')).toEqual([])
  })

  it('keeps the baseline tight (lower it when a file got cleaner)', () => {
    const shrunk = Object.entries(baseline)
      .filter(([file, n]) => (found.get(file)?.length ?? 0) < n)
      .map(([file, n]) => `${file}: ${found.get(file)?.length ?? 0} (baseline ${n})`)
    expect(
      shrunk,
      'Run UPDATE_LITERAL_DEBT=1 npx vitest run src/lib/__tests__/literal-ui-text-ratchet.test.ts'
    ).toEqual([])
  })
})

describe('literal UI text finder', () => {
  it('honours the i18n-ok escape on the line and the line above', () => {
    const src = `
      export const A = () => (
        <div>
          <span title="Docker Hub" /> {/* i18n-ok: product name */}
          {/* i18n-ok: code sample */}
          <code aria-label="curl example" />
          <b title="Plain words here" />
        </div>
      )
    `
    expect(findLiteralUiText('x.tsx', src).map((f) => f.text)).toEqual(['title="Plain words here"'])
  })
})
