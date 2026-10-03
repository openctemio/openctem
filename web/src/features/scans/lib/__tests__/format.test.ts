import { describe, expect, it } from 'vitest'

import { formatScanDate, formatScanDuration } from '../format'

describe('scan formatting', () => {
  it('formats durations in the largest two units', () => {
    expect(formatScanDuration(undefined)).toBe('-')
    expect(formatScanDuration(42_000)).toBe('42s')
    expect(formatScanDuration(192_000)).toBe('3m 12s')
    expect(formatScanDuration(3_900_000)).toBe('1h 5m')
  })

  it('shows a dash without a date', () => {
    expect(formatScanDate(undefined)).toBe('-')
    expect(formatScanDate('2026-10-02T15:41:00Z')).toMatch(/Oct 2/)
  })
})
