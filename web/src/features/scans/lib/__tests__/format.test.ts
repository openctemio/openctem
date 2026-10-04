import { describe, expect, it } from 'vitest'

import { formatScanDate, formatScanDuration, scanSuccessRate } from '../format'

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

describe('scanSuccessRate', () => {
  it('is null before any run finished (not 0%)', () => {
    expect(scanSuccessRate({ successful_runs: 0, failed_runs: 0 })).toBeNull()
  })
  it('divides by finished runs, not by every run started', () => {
    // 4 failures and nothing else is 0%, never a high rate.
    expect(scanSuccessRate({ successful_runs: 0, failed_runs: 4 })).toBe(0)
    expect(scanSuccessRate({ successful_runs: 3, failed_runs: 1 })).toBe(75)
    expect(scanSuccessRate({ successful_runs: 2, failed_runs: 1 })).toBe(67)
    expect(scanSuccessRate({ successful_runs: 5, failed_runs: 0 })).toBe(100)
  })
  it('counts a partial run as settled but not as a success', () => {
    expect(scanSuccessRate({ successful_runs: 3, failed_runs: 0, partial_runs: 1 })).toBe(75)
    expect(scanSuccessRate({ successful_runs: 0, failed_runs: 0, partial_runs: 2 })).toBe(0)
  })
})
