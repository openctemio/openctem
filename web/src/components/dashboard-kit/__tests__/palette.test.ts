import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
// The validator is a plain Node script so CI and people can run it directly.
import {
  accentBandHits,
  checkAll,
  validateCategorical,
} from '../../../../scripts/check-palette.mjs'
import palette from '@/lib/chart-palette.json'
import { categoricalVar, seriesVar } from '@/lib/chart-palette'

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
    expect(seriesVar('P0', 0)).toBe('var(--viz-sev-critical)')
    expect(seriesVar('fixed', 0)).toBe('var(--viz-div-fixed)')
    expect(categoricalVar(0)).toBe('var(--viz-cat-1)')
    expect(categoricalVar(8)).toBe('var(--viz-cat-other)')
  })
})
