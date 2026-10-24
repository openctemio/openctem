import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
// The validator is a plain Node script so CI and people can run it directly.
import {
  accentBandHits,
  checkAll,
  validateCategorical,
  validateOrdinal,
} from '../../../../scripts/check-palette.mjs'
import palette from '@/lib/chart-palette.json'
import { categoricalVar, levelVar, seriesFill, seriesVar } from '@/lib/chart-palette'

const WEB = path.resolve(__dirname, '../../../..')

describe('chart palettes', () => {
  it('pass validation and match the theme tokens in light and dark', () => {
    const css = readFileSync(path.join(WEB, 'src/styles/theme.css'), 'utf8')
    const { fails } = checkAll(palette, css)
    expect(fails).toEqual([])
  })

  it('the previously shipped severity colours fail (the reason for this palette)', () => {
    const { fails } = validateCategorical(['#ef4444', '#f97316', '#eab308', '#3b82f6'], {
      mode: 'light',
      surface: '#ffffff',
    })
    expect(fails.length).toBeGreaterThan(0)
  })

  it('keep data colours out of the accent band (the brand teal marks where to act)', () => {
    expect(accentBandHits(['#0d9488', '#14b8a6', '#1baf7a'])).toEqual(['#0d9488', '#14b8a6'])
    const teal = structuredClone(palette)
    teal.categorical.light[2] = '#14b8a6'
    expect(checkAll(teal, null).fails.join('\n')).toMatch(/accent band light: #14b8a6/)
  })

  it('assigns colours by entity, never cycling', () => {
    expect(seriesVar('critical', 5)).toBe('var(--viz-sev-critical)')
    expect(seriesVar('P0', 0)).toBe('var(--prio-0)')
    expect(seriesVar('fixed', 0)).toBe('var(--viz-div-fixed)')
    expect(categoricalVar(0)).toBe('var(--viz-cat-1)')
    expect(categoricalVar(8)).toBe('var(--viz-cat-other)')
  })

  it('the previously shipped priority ramp fails the ordinal rule (the reason for the new one)', () => {
    // P2 and P3 had the same lightness: one colour to a reader with tritanopia.
    const old = validateOrdinal(['#5b21b6', '#7c3aed', '#8f6ee6', '#7d8799'], {
      surface: '#ffffff',
    })
    expect(old.fails.join('\n')).toMatch(/lightness change/)
    expect(validateOrdinal(palette.priority.light, { surface: '#ffffff' }).fails).toEqual([])
    expect(
      validateOrdinal(palette.priority.dark, { surface: palette.surfaces.dark }).fails
    ).toEqual([])
  })

  it('"none" is a hatch and SLA states take the health colours, never a categorical slot', () => {
    expect(seriesVar('none', 3)).toBe('var(--viz-prio-none)')
    expect(seriesFill('none', 3)).toMatch(/^repeating-linear-gradient\(.*var\(--viz-prio-none\)/)
    expect(seriesFill('P1', 1)).toBe('var(--prio-1)')
    expect(seriesVar('breached', 0)).toBe('var(--hl-down)')
    expect(seriesVar('warning', 1)).toBe('var(--hl-warn)')
    expect(seriesVar('ok', 2)).toBe('var(--hl-ok)')
    // Prototype names are ordinary keys.
    expect(seriesVar('toString', 0)).toBe('var(--viz-cat-1)')
    expect(levelVar('critical')).toBe('var(--viz-lvl-critical)')
  })
})
