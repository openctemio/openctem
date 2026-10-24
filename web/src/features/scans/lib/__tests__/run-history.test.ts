import { describe, expect, it } from 'vitest'

import { MIN_RUNS_FOR_RATE, runOutcome, successRate, summarizeRuns } from '../run-history'

const runs = (...statuses: string[]) => statuses.map((status) => ({ status }))

describe('runOutcome', () => {
  it('maps every run state to one outcome', () => {
    expect(runOutcome('completed')).toBe('ok')
    expect(runOutcome('partial')).toBe('gaps')
    expect(runOutcome('failed')).toBe('failed')
    expect(runOutcome('timeout')).toBe('failed')
    expect(runOutcome('blocked')).toBe('blocked')
    expect(runOutcome('canceled')).toBe('canceled')
    expect(runOutcome('cancelled')).toBe('canceled')
    expect(runOutcome('running')).toBe('live')
    expect(runOutcome('pending')).toBe('live')
    expect(runOutcome('something-new')).toBe('unknown')
  })
})

describe('summarizeRuns', () => {
  it('counts partial runs as successes: a target-side gap is not a failure', () => {
    const s = summarizeRuns(runs('partial', 'partial', 'partial'))
    expect(s.rate).toBe(100)
    expect(s.gaps).toBe(3)
  })

  it('leaves blocked, canceled and live runs out of the rate', () => {
    // The live "Daily external recon" history: 13 failed, 3 partial, 14 blocked.
    const history = [
      ...Array(14).fill('blocked'),
      ...Array(13).fill('failed'),
      ...Array(3).fill('partial'),
      'canceled',
      'running',
    ]
    const s = summarizeRuns(runs(...history))
    expect(s.counted).toBe(16)
    expect(s.blocked).toBe(14)
    expect(s.canceled).toBe(1)
    expect(s.live).toBe(1)
    expect(s.rate).toBe(19)
  })

  it('has no rate below the minimum number of counted runs', () => {
    expect(MIN_RUNS_FOR_RATE).toBe(3)
    expect(summarizeRuns(runs('completed', 'failed')).rate).toBeNull()
    expect(summarizeRuns(runs('blocked', 'blocked', 'blocked', 'completed')).rate).toBeNull()
    expect(summarizeRuns([]).rate).toBeNull()
  })

  it('agrees with successRate on the same counts', () => {
    expect(successRate(2, 1, 1)).toBe(75)
    expect(summarizeRuns(runs('completed', 'completed', 'partial', 'failed')).rate).toBe(75)
  })
})
