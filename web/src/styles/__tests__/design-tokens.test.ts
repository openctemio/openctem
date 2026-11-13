import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * The UI v2 size tokens in src/styles/theme.css: the type roles, the control
 * scale, row density and spacing (research/513 B.3). Colours are covered by
 * contrast.test.ts. A value that the design has not settled yet sits behind
 * one token marked OPEN; this test pins today's value so a change is a
 * deliberate edit of this file too.
 */

const css = readFileSync(path.resolve(__dirname, '../theme.css'), 'utf8')

/** Every `--name: value;` declaration in the block that starts at `head`. */
function block(head: string, from = 0): Record<string, string> {
  const at = css.indexOf(head, from)
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
const phone = block('@media (max-width: 767px)')

/** rem or px to px, following var() through :root. */
function px(value: string, scope: Record<string, string> = root, depth = 0): number {
  const ref = /^var\((--[a-z0-9-]+)\)$/.exec(value)
  if (ref && depth < 6) return px(scope[ref[1]] ?? root[ref[1]], scope, depth + 1)
  const rem = /^([\d.]+)rem$/.exec(value)
  if (rem) return Number(rem[1]) * 16
  const p = /^([\d.]+)px$/.exec(value)
  if (p) return Number(p[1])
  throw new Error(`not a length: ${value}`)
}

function role(name: string, scope = root) {
  return {
    size: px(theme[`--text-${name}`], scope),
    line: px(theme[`--text-${name}--line-height`], scope),
    weight: Number(theme[`--text-${name}--font-weight`] ?? 400),
  }
}

describe('type roles', () => {
  const desktop: Record<string, [number, number, number]> = {
    cap: [12, 16, 400],
    'cap-m': [12, 16, 500],
    code: [12, 20, 400],
    dense: [13, 20, 400],
    body: [14, 20, 400],
    card: [14, 20, 600],
    section: [16, 24, 600],
    dialog: [20, 28, 600],
    page: [24, 32, 600],
    figure: [24, 32, 600],
    'figure-lead': [32, 40, 600],
    hero: [48, 56, 600],
    wall: [56, 64, 600],
  }
  for (const [name, [size, line, weight]] of Object.entries(desktop)) {
    it(`text-${name} is ${size}/${line} at ${weight}`, () => {
      expect(role(name)).toEqual({ size, line, weight })
    })
  }

  it('below 768px the page title is 20/28 and figures step down', () => {
    const scope = { ...root, ...phone }
    expect(role('page', scope)).toMatchObject({ size: 20, line: 28 })
    expect(role('figure', scope)).toMatchObject({ size: 20, line: 28 })
    expect(role('figure-lead', scope)).toMatchObject({ size: 24, line: 32 })
  })

  it('keeps the research/244 names as aliases of the roles', () => {
    expect(role('title')).toEqual(role('page'))
    expect(role('meta')).toEqual(role('cap'))
    expect(role('data')).toMatchObject({ size: 12, line: 20 })
    expect(role('kpi')).toEqual(role('figure'))
  })

  it('uses only the weights 400, 500 and 600', () => {
    const weights = Object.entries(theme)
      .filter(([k]) => k.endsWith('--font-weight'))
      .map(([, v]) => Number(v))
    expect(weights.every((w) => w === 500 || w === 600)).toBe(true)
    expect(css).not.toMatch(/font-weight:\s*(700|bold)/)
  })

  it('nothing under 12px', () => {
    for (const [k, v] of Object.entries(theme)) {
      if (!/^--text-[a-z]+(-[a-z]+)*$/.test(k)) continue
      expect(px(v), k).toBeGreaterThanOrEqual(12)
    }
  })
})

describe('control scale and rows', () => {
  it('32 default, 28 dense, 26 segment, 24 info, 36 entry; phone 36 / 32 / 40, touch target 44', () => {
    expect(px(root['--control-h'])).toBe(32)
    expect(px(root['--control-h-sm'])).toBe(28)
    expect(px(root['--control-h-seg'])).toBe(26)
    expect(px(root['--control-h-xs'])).toBe(24)
    expect(px(root['--control-h-entry'])).toBe(36)
    expect(px(root['--control-h-touch'])).toBe(36)
    expect(px(root['--control-h-touch-sm'])).toBe(32)
    expect(px(root['--control-h-touch-lg'])).toBe(40)
    expect(px(root['--touch-target'])).toBe(44)
  })

  it('every control height is a Tailwind spacing key (h-control, h-control-sm, ...)', () => {
    for (const k of [
      '',
      '-sm',
      '-seg',
      '-xs',
      '-entry',
      '-touch',
      '-touch-sm',
      '-touch-lg',
      '-field',
      '-dense',
    ]) {
      expect(theme[`--spacing-control${k}`]).toBe(`var(--control-h${k})`)
    }
    expect(theme['--spacing-row']).toBe('var(--row-h)')
    expect(theme['--spacing-touch-target']).toBe('var(--touch-target)')
  })

  it('rows are 40 by default, 32 compact, 52 comfortable', () => {
    expect(px(root['--row-h'])).toBe(40)
    expect(px(block("[data-density='compact']")['--row-h'])).toBe(32)
    expect(px(block("[data-density='comfortable']")['--row-h'])).toBe(52)
  })
})

describe('spacing', () => {
  it('4, 8, 12, 16, 24, 32; section 16; page 24', () => {
    expect(
      ['--sp-1', '--sp-2', '--sp-3', '--sp-4', '--sp-6', '--sp-8'].map((k) => px(root[k]))
    ).toEqual([4, 8, 12, 16, 24, 32])
    expect(px(theme['--spacing-section'])).toBe(16)
    expect(px(theme['--spacing-page-tight'])).toBe(16)
    expect(px(theme['--spacing-page'])).toBe(24)
  })
})

describe('fields share the row height (freeze item 1, decided)', () => {
  it('fields and the small sizes are 32 in the app', () => {
    expect(px(root['--control-h-field'])).toBe(32)
    expect(px(root['--control-h-dense'])).toBe(32)
  })
  it('the small sizes are 28 in a dense place', () => {
    expect(px(block("[data-control-density='dense']")['--control-h-dense'], { ...root })).toBe(28)
  })
  it('every control is 36 on an entry page', () => {
    const entry = block("[data-control-scale='entry']")
    for (const k of ['--control-h', '--control-h-field', '--control-h-dense'])
      expect(px(entry[k]), k).toBe(36)
  })
})

describe('values the design has not settled (one token each, today’s value)', () => {
  it('dialog radius stays 8 (freeze item 7)', () => {
    expect(px(theme['--radius-dialog'])).toBe(8)
  })
  it('the overlay shadow is unchanged (freeze item 9)', () => {
    expect(root['--shadow-overlay']).toBe(
      '0 8px 24px rgb(10 22 40 / 0.12), 0 1px 2px rgb(10 22 40 / 0.08)'
    )
  })
})
