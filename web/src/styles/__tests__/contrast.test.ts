import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { ACCENT_BAND, contrast, oklch } from '../../../scripts/check-palette.mjs'

/**
 * Brand tokens in src/styles/theme.css: the brand values themselves, and
 * every text and control pair at WCAG AA in light (`:root`) and dark
 * (`.dark`). Runs in web CI with the rest of vitest, so a token edit that
 * breaks contrast fails the pull request.
 */

const css = readFileSync(path.resolve(__dirname, '../theme.css'), 'utf8')

function block(selector: string): Record<string, string> {
  const at = css.indexOf(`\n${selector} {`)
  if (at < 0) throw new Error(`no ${selector} block`)
  const body = css.slice(css.indexOf('{', at) + 1, css.indexOf('\n}', at))
  const out: Record<string, string> = {}
  for (const m of body.matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim()
  return out
}

const light = block(':root')
const dark = { ...light, ...block('.dark') }

/** Resolves var() chains to a #rrggbb value within one theme. */
function hex(theme: Record<string, string>, name: string, depth = 0): string {
  const v = theme[name]
  if (v === undefined) throw new Error(`${name} is not defined`)
  const ref = /^var\((--[a-z0-9-]+)\)$/.exec(v)
  if (ref && depth < 8) return hex(theme, ref[1], depth + 1)
  if (!/^#[0-9a-f]{6}$/i.test(v)) throw new Error(`${name} is ${v}, expected #rrggbb`)
  return v.toLowerCase()
}

const THEMES = { light, dark } as const
const SURFACES = ['--background', '--card', '--popover', '--surface-raised']
const SEV = ['critical', 'high', 'medium', 'low', 'info']
const PRIO = [0, 1, 2, 3]

describe('brand tokens', () => {
  it('use the brand palette: paper and ink grounds, the teal accent', () => {
    expect(hex(light, '--background')).toBe('#fafaf9')
    expect(hex(light, '--foreground')).toBe('#0a1628')
    expect(hex(light, '--muted-foreground')).toBe('#525252')
    expect(hex(dark, '--background')).toBe('#0a1628')
    expect(hex(dark, '--foreground')).toBe('#fafaf9')
    expect(hex(light, '--signal')).toBe('#0f766e')
    expect(hex(dark, '--signal')).toBe('#14b8a6')
    expect(hex(light, '--brand')).toBe('#0d9488')
    // Text and primary are ink (light) / paper (dark); teal is only the accent.
    expect(hex(light, '--primary')).toBe('#0a1628')
    expect(hex(dark, '--primary')).toBe('#fafaf9')
    expect(light['--ring']).toBe('var(--signal)')
  })

  it('build dark surfaces on the ink hue, never on teal', () => {
    for (const name of ['--background', '--card', '--popover', '--surface-raised', '--border']) {
      const [, chroma, hue] = oklch(hex(dark, name)) as number[]
      expect(chroma, name).toBeGreaterThan(0.02)
      expect(hue, `${name} hue`).toBeGreaterThanOrEqual(245)
      expect(hue, `${name} hue`).toBeLessThanOrEqual(270)
    }
  })

  it('use a smaller radius (4 / 6 / 8 by role)', () => {
    expect(light['--radius']).toBe('0.5rem')
  })

  for (const [mode, t] of Object.entries(THEMES)) {
    const pair = (fg: string, bg: string, min: number) => {
      const r = contrast(hex(t, fg), hex(t, bg))
      expect(
        r,
        `${mode}: ${fg} on ${bg} is ${r.toFixed(2)}:1, needs ${min}:1`
      ).toBeGreaterThanOrEqual(min)
    }

    it(`${mode}: body, muted and dim text read at AA on every surface`, () => {
      for (const bg of SURFACES) {
        pair('--foreground', bg, 7)
        pair('--muted-foreground', bg, 4.5)
        pair('--fg-dim', bg, 4.5)
      }
    })

    it(`${mode}: the accent, links, focus ring and inputs`, () => {
      pair('--signal-ink', '--signal', 4.5)
      pair('--primary-foreground', '--primary', 4.5)
      for (const bg of ['--background', '--card']) {
        pair('--signal-text', bg, 4.5)
        pair('--ring', bg, 3)
        pair('--input', bg, 3)
      }
    })

    it(`${mode}: state colours as text, and text on the destructive fill`, () => {
      for (const s of ['--destructive', '--success', '--warning', '--info'])
        for (const bg of ['--background', '--card']) pair(s, bg, 4.5)
      pair('--destructive-foreground', '--destructive', 4.5)
    })

    it(`${mode}: priority box text at AA, marks at 3:1, edges visible`, () => {
      for (const n of PRIO) {
        pair(`--prio-${n}-fg`, `--prio-${n}-bg`, 4.5)
        for (const bg of SURFACES) pair(`--prio-${n}`, bg, 3)
        // P2 and P3 boxes are tints: their edge must separate them from the card.
        if (n >= 2) pair(`--prio-${n}-border`, '--card', 3)
      }
    })

    it(`${mode}: priority is its own system, never teal and never a severity hue`, () => {
      for (const n of PRIO) {
        for (const name of [
          `--prio-${n}`,
          `--prio-${n}-bg`,
          `--prio-${n}-fg`,
          `--prio-${n}-border`,
        ]) {
          const [, chroma, hue] = oklch(hex(t, name)) as number[]
          // Not in the accent band (teal), and the ramp stays on the ink hue.
          expect(chroma >= 0.04 && hue >= ACCENT_BAND[0] && hue <= ACCENT_BAND[1], name).toBe(false)
          expect(chroma, name).toBeLessThan(0.1)
        }
        for (const s of SEV) expect(hex(t, `--prio-${n}`)).not.toBe(hex(t, `--sev-${s}`))
      }
    })

    it(`${mode}: priority steps from P0 (strongest) to P3 (quietest) by contrast with the card`, () => {
      const c = PRIO.map((n) => contrast(hex(t, `--prio-${n}`), hex(t, '--card')))
      for (let i = 1; i < c.length; i++) expect(c[i]).toBeLessThan(c[i - 1])
    })

    it(`${mode}: severity text, marks and ink on a solid mark`, () => {
      for (const s of SEV) {
        for (const bg of SURFACES) pair(`--sev-${s}-text`, bg, 4.5)
        pair(`--sev-${s}-ink`, `--sev-${s}`, 4.5)
        // Medium (yellow) cannot reach 3:1 on white and stay yellow; it always
        // carries its label, and every chart has a table view.
        if (!(mode === 'light' && s === 'medium')) pair(`--sev-${s}`, '--card', 3)
      }
    })
  }
})
