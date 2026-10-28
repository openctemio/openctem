import { describe, expect, it } from 'vitest'
import { runDeadline } from '../run-display'
import { maxDurationInput } from '../scan-form'

const now = Date.parse('2026-10-13T13:00:00Z')

describe('runDeadline', () => {
  it('shows the time left and why while the run is open', () => {
    const d = runDeadline(
      { status: 'running', deadline_at: '2026-10-13T13:23:10Z', deadline_reason: 'platform_cap' },
      undefined,
      now
    )
    expect(d?.relative).toBe('deadline in 23m 10s')
    expect(d?.reason).toMatch(/24 h cap/)
    expect(d?.at).toBe('2026-10-13T13:23:10Z')
  })

  it('says the deadline passed while the reaper settles the run', () => {
    const d = runDeadline(
      {
        status: 'running',
        deadline_at: '2026-10-13T12:59:00Z',
        deadline_reason: 'scan_max_duration',
      },
      undefined,
      now
    )
    expect(d?.relative).toBe('deadline passed, settling')
    expect(d?.reason).toMatch(/max duration/)
  })

  it('keeps the deadline but no countdown once the run settled', () => {
    const d = runDeadline(
      { status: 'partial', deadline_at: '2026-10-13T12:59:00Z' },
      undefined,
      now
    )
    expect(d?.relative).toBeNull()
    expect(d?.reason).toMatch(/when the run started/)
  })

  it('says a claim moved the deadline to the time the work needs', () => {
    const d = runDeadline(
      { status: 'running', deadline_at: '2026-10-13T14:45:00Z', deadline_reason: 'work_estimate' },
      undefined,
      now
    )
    expect(d?.relative).toBe('deadline in 1h 45m')
    expect(d?.reason).toMatch(/queue does not count/)
  })

  it('is null without a deadline or with a bad one', () => {
    expect(runDeadline({ status: 'running' }, undefined, now)).toBeNull()
    expect(runDeadline({ status: 'running', deadline_at: 'nope' }, undefined, now)).toBeNull()
  })
})

describe('maxDurationInput', () => {
  it('empty or zero is no max duration; anything else is kept in 30s-24h', () => {
    expect(maxDurationInput('')).toBe(0)
    expect(maxDurationInput('0')).toBe(0)
    expect(maxDurationInput('-5')).toBe(0)
    expect(maxDurationInput('abc')).toBe(0)
    expect(maxDurationInput('10')).toBe(30)
    expect(maxDurationInput('7200')).toBe(7200)
    expect(maxDurationInput('999999')).toBe(86400)
  })
})
