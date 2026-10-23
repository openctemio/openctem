import { describe, it, expect } from 'vitest'
import { formatDateOnly, parseDateOnly } from '../date-only'

describe('parseDateOnly', () => {
  it('reads a date-only string as a local calendar date', () => {
    const d = parseDateOnly('2026-10-01')
    expect([d.getFullYear(), d.getMonth(), d.getDate()]).toEqual([2026, 9, 1])
    expect([d.getHours(), d.getMinutes()]).toEqual([0, 0])
  })

  it('reads a midnight-UTC DATE timestamp as the same calendar day', () => {
    const d = parseDateOnly('2026-10-01T00:00:00Z')
    expect([d.getFullYear(), d.getMonth(), d.getDate()]).toEqual([2026, 9, 1])
  })

  it('keeps real timestamps as instants', () => {
    const iso = '2026-10-01T13:45:00Z'
    expect(parseDateOnly(iso).getTime()).toBe(new Date(iso).getTime())
  })
})

describe('formatDateOnly', () => {
  it('returns an empty string for missing or invalid input', () => {
    expect(formatDateOnly(undefined)).toBe('')
    expect(formatDateOnly('')).toBe('')
    expect(formatDateOnly('not a date')).toBe('')
  })
})
