import { describe, expect, it } from 'vitest'

import { receivedBreakdown, unaccountedFindings } from '../receipt-outcomes'

const t = (_k: string, fallback?: string) => fallback ?? ''

describe('receivedBreakdown', () => {
  it('lists every place a received finding went, without empty rows', () => {
    const rows = receivedBreakdown(t, {
      received: 2942,
      new: 423,
      suppressed: 0,
      not_stored: 6,
      seen_again: 700,
      repeated: 1800,
      outcomes: { exposure: 13, split: 0 },
      unaccounted: 0,
    })
    expect(rows).toEqual([
      ['Findings received', 2942],
      ['New or reopened', 423],
      ['Seen again, unchanged', 700],
      ['Repeated in the same scan', 1800],
      ['Not stored', 6],
      ['Filed as exposures', 13],
    ])
  })

  it('shows what older receipts leave unexplained', () => {
    const rows = receivedBreakdown(t, {
      received: 10,
      new: 2,
      suppressed: 0,
      not_stored: 0,
      unaccounted: 8,
    })
    expect(rows).toContainEqual(['Not explained by older receipts', 8])
  })
})

describe('unaccountedFindings', () => {
  const c = { created: 2, stillDetected: 3, reopened: 1, suppressed: 1, failed: 1, skipped: 2 }
  it('is zero on a reconciled receipt; split adds to received; unknown codes are ignored', () => {
    expect(unaccountedFindings(13, c, { merged: 4, exposure: 1, split: 2, unknown: 50 })).toBe(0)
    expect(unaccountedFindings(15, c, { merged: 4, exposure: 1, split: 2 })).toBe(2)
  })
})
