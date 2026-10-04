import { describe, it, expect } from 'vitest'
import {
  runTriggeredByLabel,
  scanRunCounts,
  isRunInProgress,
  runTaskProgress,
  elapsedMs,
} from '../lib/run-display'

const USER_ID = '76df42a3-72d0-45da-a1c8-5a8b2a01f658'

describe('runTriggeredByLabel', () => {
  it("shows the user's name, not their id", () => {
    expect(runTriggeredByLabel({ triggered_by: USER_ID, triggered_by_name: 'Olivia Owner' })).toBe(
      'Olivia Owner'
    )
  })

  it('never shows a raw user id', () => {
    expect(runTriggeredByLabel({ triggered_by: USER_ID })).toBe('Unknown user')
  })

  it('keeps non-user triggers as sent, and nothing when there is none', () => {
    expect(runTriggeredByLabel({ triggered_by: 'system' })).toBe('system')
    expect(runTriggeredByLabel({})).toBeNull()
  })
})

describe('scanRunCounts', () => {
  const fresh = { total_runs: 0, successful_runs: 0, failed_runs: 0 }

  it('counts a run in progress (was "Total runs 0" next to a running run)', () => {
    const c = scanRunCounts(fresh, [{ status: 'running' }])
    expect(c.total).toBe(1)
    expect(c.inProgress).toBe(1)
    // No run settled yet: no rate, not a red 0%.
    expect(c.successRate).toBeNull()
  })

  it('adds in-progress runs to the finished ones; success rate is over finished runs', () => {
    const c = scanRunCounts({ total_runs: 4, successful_runs: 3, failed_runs: 1 }, [
      { status: 'queued' },
      { status: 'pending' },
      { status: 'completed' },
      { status: 'failed' },
    ])
    expect(c).toEqual({
      total: 6,
      inProgress: 2,
      successful: 3,
      partial: 0,
      failed: 1,
      successRate: 75,
    })
  })

  it('uses the scan list formula: canceled runs are out, partial runs are settled', () => {
    // 10 runs: 5 succeeded, 2 partial, 1 failed, 2 canceled.
    const c = scanRunCounts(
      { total_runs: 10, successful_runs: 5, failed_runs: 1, partial_runs: 2 },
      []
    )
    expect(c.partial).toBe(2)
    expect(c.successRate).toBe(63) // 5 / (5 + 2 + 1), not 5 / 10
  })

  it('knows which statuses are in progress', () => {
    expect(['pending', 'queued', 'running'].every((status) => isRunInProgress({ status }))).toBe(
      true
    )
    expect(
      ['completed', 'failed', 'cancelled', 'timeout'].some((status) => isRunInProgress({ status }))
    ).toBe(false)
  })
})

describe('runTaskProgress', () => {
  const base = { total: 5, queued: 1, running: 1, completed: 2, failed: 1, canceled: 0 }

  it('reads done of total and lists only the non-zero counts', () => {
    expect(runTaskProgress(base)).toEqual({
      label: '2/5 tasks',
      details: [
        { key: 'running', count: 1 },
        { key: 'queued', count: 1 },
        { key: 'failed', count: 1 },
      ],
    })
  })

  it('is null without tasks, so the page falls back to steps', () => {
    expect(runTaskProgress(undefined)).toBeNull()
    expect(runTaskProgress({ ...base, total: 0 })).toBeNull()
  })
})

describe('elapsedMs', () => {
  it('measures start to completion', () => {
    expect(
      elapsedMs({ started_at: '2026-10-04T10:00:00Z', completed_at: '2026-10-04T10:03:00Z' })
    ).toBe(180_000)
  })

  it('measures start to now while it runs', () => {
    const now = Date.parse('2026-10-04T10:01:00Z')
    expect(elapsedMs({ started_at: '2026-10-04T10:00:00Z' }, now)).toBe(60_000)
  })

  it('is undefined before the start and for impossible timestamps', () => {
    expect(elapsedMs({})).toBeUndefined()
    expect(
      elapsedMs({ started_at: '2026-10-04T10:05:00Z', completed_at: '2026-10-04T10:00:00Z' })
    ).toBeUndefined()
  })
})
