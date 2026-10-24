import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  ACCENT_BAND,
  ORDINAL_MIN_DL,
  contrast,
  deltaE,
  oklch,
  worstCvd,
} from '../../../scripts/check-palette.mjs'

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

/** Alpha-blend `fg` over `bg` (#rrggbb) at `alpha`. */
function blend(fg: string, bg: string, alpha: number): string {
  const ch = (h: string, i: number) => parseInt(h.slice(1 + i * 2, 3 + i * 2), 16)
  return (
    '#' +
    [0, 1, 2]
      .map((i) =>
        Math.round(ch(fg, i) * alpha + ch(bg, i) * (1 - alpha))
          .toString(16)
          .padStart(2, '0')
      )
      .join('')
  )
}

const THEMES = { light, dark } as const
const SURFACES = ['--background', '--card', '--popover', '--surface-raised']
const SEV = ['critical', 'high', 'medium', 'low', 'info']
const PRIO = [0, 1, 2, 3]
const STATUS_TONES = ['triage', 'open', 'progress', 'waiting', 'resolved', 'accepted', 'closed']
const HEALTH = ['ok', 'run', 'warn', 'down', 'idle']
const TAG_COLOURS = [
  'red',
  'orange',
  'amber',
  'yellow',
  'green',
  'cyan',
  'blue',
  'violet',
  'pink',
  'grey',
]
/** Minimum normal-vision delta E between a priority mark and a severity mark. */
const PRIO_SEV_MIN_DE = 10

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
        // A transparent box sits on the card.
        pair(
          `--prio-${n}-fg`,
          t[`--prio-${n}-bg`] === 'transparent' ? '--card' : `--prio-${n}-bg`,
          4.5
        )
        for (const bg of SURFACES) pair(`--prio-${n}`, bg, 3)
        // P2 and P3 boxes are tints: their edge must separate them from the card.
        if (n >= 2) pair(`--prio-${n}-border`, '--card', 3)
      }
    })

    it(`${mode}: priority is a violet system (P3 neutral), never teal, apart from every severity hue`, () => {
      for (const n of PRIO) {
        for (const name of [
          `--prio-${n}`,
          `--prio-${n}-bg`,
          `--prio-${n}-fg`,
          `--prio-${n}-border`,
        ]) {
          const v = t[name]
          if (v === 'transparent') continue
          const [, chroma, hue] = oklch(hex(t, name)) as number[]
          // Not in the accent band (teal).
          expect(chroma >= 0.04 && hue >= ACCENT_BAND[0] && hue <= ACCENT_BAND[1], name).toBe(false)
          // Violet band, except the deliberately neutral P3 and the plain white or dark text of P0.
          if (n <= 2 && chroma >= 0.04 && !name.endsWith('-fg'))
            expect(hue, `${name} hue`).toBeGreaterThanOrEqual(280)
          if (n <= 2 && chroma >= 0.04 && !name.endsWith('-fg'))
            expect(hue, `${name} hue`).toBeLessThanOrEqual(305)
        }
        for (const s of SEV) {
          expect(hex(t, `--prio-${n}`)).not.toBe(hex(t, `--sev-${s}`))
          if (n <= 2)
            expect(
              deltaE(hex(t, `--prio-${n}`), hex(t, `--sev-${s}`)),
              `--prio-${n} vs --sev-${s}`
            ).toBeGreaterThanOrEqual(PRIO_SEV_MIN_DE)
        }
      }
      // P0 sits more than 60 degrees of hue from critical.
      const hueGap = Math.abs(
        (oklch(hex(t, '--prio-0')) as number[])[2] -
          (oklch(hex(t, '--sev-critical')) as number[])[2]
      )
      expect(Math.min(hueGap, 360 - hueGap)).toBeGreaterThan(60)
    })

    it(`${mode}: status lozenge text at AA on its fill and on the card, edges visible`, () => {
      for (const tone of STATUS_TONES) {
        const fg = `--st-${tone}-fg`
        pair(fg, '--card', 4.5)
        pair(fg, '--background', 4.5)
        if (t[`--st-${tone}-bg`] !== 'transparent') pair(fg, `--st-${tone}-bg`, 4.5)
      }
      // The untouched (triage) lozenge is an empty dashed outline: the edge is its fill.
      pair('--st-triage-border', '--card', 3)
    })

    it(`${mode}: the waiting tone shares the accepted colours`, () => {
      for (const part of ['bg', 'fg', 'border'])
        expect(hex(t, `--st-waiting-${part}`)).toBe(hex(t, `--st-accepted-${part}`))
    })

    it(`${mode}: health icons are 3:1 on every surface and text stays foreground`, () => {
      for (const h of HEALTH) for (const bg of SURFACES) pair(`--hl-${h}`, bg, 3)
      for (const bg of SURFACES) pair('--foreground', bg, 7)
    })

    it(`${mode}: counter text at AA on its fill, emphasis too`, () => {
      pair('--ctr-fg', '--ctr-bg', 4.5)
      pair('--ctr-em-fg', '--ctr-em-bg', 4.5)
      pair('--ctr-fg', '--card', 4.5)
      pair('--ctr-em-bg', '--card', 3)
    })

    it(`${mode}: marker text and outline`, () => {
      pair('--muted-foreground', '--card', 4.5)
      pair('--border-strong', '--card', 3)
    })

    it(`${mode}: tag palette dots are 3:1 on the card, distinct, and never teal`, () => {
      const seen = new Set<string>()
      for (const c of TAG_COLOURS) {
        pair(`--tag-${c}`, '--card', 3)
        pair(`--tag-${c}`, '--background', 3)
        const v = hex(t, `--tag-${c}`)
        expect(seen.has(v), `${c} duplicates another tag colour`).toBe(false)
        seen.add(v)
        const [, chroma, hue] = oklch(v) as number[]
        expect(
          chroma >= 0.04 && hue >= ACCENT_BAND[0] && hue <= ACCENT_BAND[1],
          `${c} sits in the accent band`
        ).toBe(false)
      }
    })

    it(`${mode}: no status tint of a state colour at 15% alpha is used for text (it fails AA)`, () => {
      // Documents why the /15 tint pills were replaced: text-success on bg-success/15.
      for (const s of ['--success', '--warning']) {
        const fg = hex(t, s)
        const card = hex(t, '--card')
        const tint = blend(fg, card, 0.15)
        const r = contrast(fg, tint)
        if (mode === 'light') expect(r, `${s} on its 15% tint`).toBeLessThan(4.5)
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

  /*
   * The label colour system (research/257): every family that must be told
   * apart is measured here, so a token edit that makes two levels or two
   * families look alike fails CI. Lightness is the channel that survives every
   * colour-vision deficiency, so ordinal scales are stepped by it.
   */
  for (const [mode, t] of Object.entries(THEMES)) {
    const L = (name: string) => (oklch(hex(t, name)) as number[])[0]
    const de = (a: string, b: string) => deltaE(hex(t, a), hex(t, b))
    const cvd = (a: string, b: string) => worstCvd(hex(t, a), hex(t, b))
    const pair = (fg: string, bg: string, min: number) =>
      expect(contrast(hex(t, fg), hex(t, bg)), `${mode}: ${fg} on ${bg}`).toBeGreaterThanOrEqual(
        min
      )

    const ordinal: Record<string, string[]> = {
      priority: PRIO.map((n) => `--prio-${n}`),
      level: ['critical', 'high', 'medium', 'low'].map((k) => `--viz-lvl-${k}`),
    }
    for (const [family, steps] of Object.entries(ordinal)) {
      it(`${mode}: ${family} steps by lightness, strongest first, apart for colour blindness`, () => {
        const card = L('--card')
        for (let i = 1; i < steps.length; i++) {
          const a = steps[i - 1]
          const b = steps[i]
          const step = Math.abs(L(a) - card) - Math.abs(L(b) - card)
          expect(step, `${a} -> ${b} lightness step`).toBeGreaterThanOrEqual(ORDINAL_MIN_DL)
          expect(cvd(a, b), `${a} vs ${b} worst colour-vision delta E`).toBeGreaterThanOrEqual(8)
          expect(de(a, b), `${a} vs ${b} delta E`).toBeGreaterThanOrEqual(10)
        }
        for (const s of steps) for (const bg of SURFACES) pair(s, bg, 3)
      })
    }

    it(`${mode}: the priority box uses the chart steps (badge and chart agree)`, () => {
      expect(hex(t, '--prio-0-bg')).toBe(hex(t, '--prio-0'))
      for (const n of PRIO) expect(hex(t, `--prio-${n}-border`)).toBe(hex(t, `--prio-${n}`))
      pair('--viz-prio-none', '--card', 3)
    })

    it(`${mode}: health ok, warn and down stay apart for colour blindness`, () => {
      const states = ['--hl-ok', '--hl-warn', '--hl-down']
      for (let i = 0; i < states.length; i++)
        for (let j = i + 1; j < states.length; j++) {
          expect(cvd(states[i], states[j]), `${states[i]} vs ${states[j]}`).toBeGreaterThanOrEqual(
            7
          )
          expect(de(states[i], states[j]), `${states[i]} vs ${states[j]}`).toBeGreaterThanOrEqual(
            15
          )
        }
      // Running and ok differ by hue only; each has its own glyph.
      expect(de('--hl-ok', '--hl-run')).toBeGreaterThanOrEqual(20)
      expect(cvd('--hl-ok', '--hl-run')).toBeGreaterThanOrEqual(5)
    })

    it(`${mode}: families that share a row do not share a colour`, () => {
      // A failed run next to a critical finding count; a warning next to High.
      expect(de('--hl-down', '--sev-critical')).toBeGreaterThanOrEqual(7)
      expect(de('--hl-warn', '--sev-high')).toBeGreaterThanOrEqual(10)
      // Tags sit next to the priority box: the tag violet is not a priority step.
      for (const n of PRIO) expect(de('--tag-violet', `--prio-${n}`)).toBeGreaterThanOrEqual(7)
      // Criticality levels are ink, never a severity hue.
      for (const k of ['critical', 'high', 'medium', 'low']) {
        const [, chroma] = oklch(hex(t, `--viz-lvl-${k}`)) as number[]
        expect(chroma, `--viz-lvl-${k} chroma`).toBeLessThan(0.06)
      }
    })

    it(`${mode}: workflow status text tones are distinct from each other`, () => {
      const tones = ['progress', 'resolved', 'accepted'].map((k) => `--st-${k}-fg`)
      for (let i = 0; i < tones.length; i++)
        for (let j = i + 1; j < tones.length; j++)
          expect(de(tones[i], tones[j]), `${tones[i]} vs ${tones[j]}`).toBeGreaterThanOrEqual(15)
    })

    it(`${mode}: severity marks stay apart from their neighbours`, () => {
      for (let i = 1; i < SEV.length; i++)
        expect(de(`--sev-${SEV[i - 1]}`, `--sev-${SEV[i]}`)).toBeGreaterThanOrEqual(15)
    })

    it(`${mode}: the soft state pill (text on its own 10% tint) is below AA in light mode`, () => {
      // Why state text never sits on its own 10% tint: use StatusLozenge or DueChip.
      const r = (s: string) => contrast(hex(t, s), blend(hex(t, s), hex(t, '--card'), 0.1))
      if (mode === 'light') {
        expect(r('--success')).toBeLessThan(4.5)
        expect(r('--warning')).toBeLessThan(4.5)
      }
    })
  }
})
