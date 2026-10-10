import { describe, expect, it } from 'vitest'

import { hasSchedule, lastRunOf, lastRunReason, scanTypeLabel, scheduleOn } from '../scan-status'

describe('hasSchedule / scheduleOn', () => {
  it('a manual scan has no schedule to switch', () => {
    expect(hasSchedule({ schedule_type: 'manual' })).toBe(false)
    expect(hasSchedule({ schedule_type: 'daily' })).toBe(true)
  })

  it('the schedule is on only for an enabled, unpaused scan', () => {
    expect(scheduleOn({ status: 'active' })).toBe(true)
    expect(scheduleOn({ status: 'paused' })).toBe(false)
    expect(scheduleOn({ status: 'disabled' })).toBe(false)
  })
})

describe('lastRunOf', () => {
  it('prefers the API last_run', () => {
    const run = { id: 'r1', status: 'running', created_at: '2026-10-07T04:00:00Z', progress: 42 }
    expect(lastRunOf({ last_run: run, last_run_status: 'completed' })).toBe(run)
  })

  it('falls back to the flat fields of an older API', () => {
    expect(
      lastRunOf({
        last_run_id: 'r2',
        last_run_at: '2026-10-07T04:00:00Z',
        last_run_status: 'failed',
      })
    ).toEqual({ id: 'r2', status: 'failed', created_at: '2026-10-07T04:00:00Z' })
  })

  it('a time without a run is not a run (the old "Last run: today, Runs: 0")', () => {
    expect(lastRunOf({ last_run_at: '2026-10-07T04:17:00Z', last_run_status: 'failed' })).toBe(null)
    expect(lastRunOf({})).toBe(null)
  })
})

describe('lastRunReason', () => {
  it('names the refusal and keeps the message', () => {
    expect(
      lastRunReason({
        id: 'r',
        status: 'blocked',
        created_at: '',
        refusal_code: 'WILDCARD_TARGET',
        error_message: 'Target "*.x" is a pattern',
      })
    ).toBe('Wildcard target not allowed: Target "*.x" is a pattern')
  })

  it('shows an unknown code as sent, and escapes control characters', () => {
    expect(
      lastRunReason({ id: 'r', status: 'blocked', created_at: '', refusal_code: 'NEW_CODE' })
    ).toBe('NEW_CODE')
    const reason = lastRunReason({
      id: 'r',
      status: 'failed',
      created_at: '',
      error_message: 'bad‮txt',
    })
    expect(reason).not.toContain('‮')
  })

  it('nothing to say for a run without a reason', () => {
    expect(lastRunReason({ id: 'r', status: 'completed', created_at: '' })).toBeUndefined()
    expect(lastRunReason(null)).toBeUndefined()
  })
})

describe('scanTypeLabel', () => {
  it("shows the workflow's name, not 'Single Scan' on every row", () => {
    expect(scanTypeLabel({ scan_type: 'workflow', scan_workflow_name: 'External recon' })).toEqual({
      label: 'External recon',
      kind: 'workflow',
    })
    expect(scanTypeLabel({ scan_type: 'workflow' })).toEqual({
      label: 'Workflow',
      kind: 'workflow',
    })
  })

  it('shows the tool of a single check', () => {
    expect(scanTypeLabel({ scan_type: 'single', scanner_name: 'nuclei' })).toEqual({
      label: 'nuclei',
      kind: 'single',
    })
    expect(scanTypeLabel({ scan_type: 'single' }).label).toBe('Single check')
  })
})
