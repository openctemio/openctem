import { describe, it, expect } from 'vitest'
import { formatPct, formatCount, formatTickDate, PERIOD_OPTIONS } from '../format'

describe('formatPct', () => {
  it('is whole percent', () => {
    expect(formatPct(94.3)).toBe('94%')
    expect(formatPct(0)).toBe('0%')
    expect(formatPct(100)).toBe('100%')
  })
  it('shows <1% for a non-zero rate that would round to zero', () => {
    expect(formatPct(0.4)).toBe('<1%')
  })
  it('is a dash when not measured', () => {
    expect(formatPct(null)).toBe('—')
    expect(formatPct(undefined)).toBe('—')
    expect(formatPct(Number.NaN)).toBe('—')
  })
  it('is a dash when the rate rests on fewer than 5 items', () => {
    expect(formatPct(94.3, { n: 4 })).toBe('—')
    expect(formatPct(94.3, { n: 5 })).toBe('94%')
    expect(formatPct(94.3, { n: 7 })).toBe('94%')
  })
})

describe('shared period model', () => {
  it('offers the same three windows everywhere', () => {
    expect(PERIOD_OPTIONS.map((o) => o.value)).toEqual(['30', '90', '365'])
  })
  it('formats counts and tick dates in the given locale', () => {
    expect(formatCount(1234567, 'de')).toBe('1.234.567')
    expect(formatTickDate('2026-10-05', 'en')).toBe('Oct 5')
    expect(formatTickDate('not a date', 'en')).toBe('not a date')
  })
})
