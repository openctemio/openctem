import { describe, expect, it } from 'vitest'

import { findingsOverview } from '../findings-overview'

const base = {
  total: 10,
  by_severity: {},
  by_status: {},
  by_source: {},
  open_count: 6,
  resolved_count: 2,
}

describe('findingsOverview', () => {
  it('reads Total and Open from by_state, the numbers the tabs show', () => {
    const o = findingsOverview({
      ...base,
      by_state: { open: 5, fixed: 2, dispositioned: 1, all: 8 },
      open_by_severity: { critical: 1, high: 2 },
      kev_open: 1,
      sla_breached: 3,
      awaiting_verification: 4,
    })
    expect(o).toEqual({
      total: 8,
      open: 5,
      criticalOpen: 1,
      highOpen: 2,
      overdue: 3,
      kev: 1,
      awaitingVerification: 4,
    })
  })

  it('shows a dash for a number an older API does not send, never a wrong one', () => {
    const o = findingsOverview(base)
    expect(o.open).toBe('—')
    expect(o.criticalOpen).toBe('—')
    expect(o.awaitingVerification).toBe('—')
    expect(o.total).toBe(10)
  })

  it('a severity with no open findings is zero', () => {
    expect(findingsOverview({ ...base, open_by_severity: {} }).highOpen).toBe(0)
  })

  it('zeros while loading', () => {
    expect(findingsOverview(undefined).total).toBe(0)
  })
})
