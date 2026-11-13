import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * "Sizes" in web/docs/ui-style-contract.md is the one written table of the
 * console's sizes. Every row that names a token must match the value the
 * theme declares, so the doc and src/styles/theme.css cannot drift apart.
 */

const css = readFileSync(path.resolve(__dirname, '../theme.css'), 'utf8')
const doc = readFileSync(path.resolve(__dirname, '../../../docs/ui-style-contract.md'), 'utf8')

/** Declarations of the block that starts at `head` (nested braces handled). */
function block(head: string): Record<string, string> {
  const at = css.indexOf(head)
  if (at < 0) throw new Error(`no block ${head}`)
  let depth = 0
  let end = at
  for (let i = css.indexOf('{', at); i < css.length; i++) {
    if (css[i] === '{') depth++
    if (css[i] === '}' && --depth === 0) {
      end = i
      break
    }
  }
  const out: Record<string, string> = {}
  for (const m of css.slice(at, end).matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g))
    out[m[1]] = m[2].trim()
  return out
}

const root = block('\n:root {')
const theme = block('\n@theme inline {')
const phone = { ...root, ...block('@media (max-width: 767px)') }

function px(value: string | undefined, scope: Record<string, string>, depth = 0): number {
  if (value === undefined) throw new Error('undefined token')
  const ref = /^var\((--[a-z0-9-]+)\)$/.exec(value)
  if (ref && depth < 8) return px(scope[ref[1]] ?? root[ref[1]] ?? theme[ref[1]], scope, depth + 1)
  const calc = /^calc\(var\((--[a-z0-9-]+)\)\s*([+-])\s*([\d.]+)px\)$/.exec(value)
  if (calc) {
    const base = px(scope[calc[1]] ?? root[calc[1]], scope, depth + 1)
    return calc[2] === '+' ? base + Number(calc[3]) : base - Number(calc[3])
  }
  const rem = /^([\d.]+)rem$/.exec(value)
  if (rem) return Number(rem[1]) * 16
  const p = /^([\d.]+)px$/.exec(value)
  if (p) return Number(p[1])
  throw new Error(`not a length: ${value}`)
}

/** Rows of the markdown table under `### <heading>` in the Sizes section. */
function table(heading: string): string[][] {
  const sizes = doc.slice(
    doc.indexOf('## Sizes'),
    doc.indexOf('\n## ', doc.indexOf('## Sizes') + 1)
  )
  const at = sizes.indexOf(`### ${heading}`)
  if (at < 0) throw new Error(`no "${heading}" table in Sizes`)
  const lines = sizes.slice(at).split('\n')
  const rows: string[][] = []
  let started = false
  for (const line of lines.slice(1)) {
    if (line.startsWith('|')) {
      started = true
      const cells = line
        .split('|')
        .slice(1, -1)
        .map((c) => c.trim())
      if (!/^-+$/.test(cells[0])) rows.push(cells)
    } else if (started) break
  }
  return rows.slice(1) // header row
}

const code = (cell: string) => [...cell.matchAll(/`([^`]+)`/g)].map((m) => m[1])

describe('the Sizes section of the UI style contract', () => {
  for (const heading of ['Control heights', 'Spacing', 'Row density', 'Radii']) {
    it(`"${heading}" matches theme.css`, () => {
      const rows = table(heading)
      expect(rows.length).toBeGreaterThan(0)
      for (const [label, tokenCell, value] of rows) {
        const [token, selector] = code(tokenCell)
        const scope = selector ? { ...root, ...block(`\n${selector} {`) } : root
        const declared = scope[token] ?? theme[token]
        expect(px(declared, scope), `${heading}: ${label} (${token})`).toBe(Number(value))
      }
    })
  }

  it('"Type roles" matches theme.css, phone column included', () => {
    const rows = table('Type roles')
    expect(rows.length).toBe(13)
    for (const [label, classCell, sizeLine, weight, phoneSizeLine] of rows) {
      const role = code(classCell)[0].replace(/^text-/, '')
      const size = (scope: Record<string, string>) =>
        `${px(theme[`--text-${role}`], scope)}/${px(theme[`--text-${role}--line-height`], scope)}`
      expect(size(root), label).toBe(sizeLine)
      expect(size(phone), `${label} below 768px`).toBe(phoneSizeLine)
      expect(Number(theme[`--text-${role}--font-weight`] ?? 400), label).toBe(Number(weight))
    }
  })
})
