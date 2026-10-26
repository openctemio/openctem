import { describe, expect, it } from 'vitest'
import { taskProgressNote } from '../run-tasks-table'

const now = Date.parse('2026-10-13T13:00:00Z')

describe('taskProgressNote', () => {
  it('shows finished targets, the last one and the budget of a running task', () => {
    const n = taskProgressNote(
      {
        status: 'running',
        progress: { done: 12, total: 72, last_progress_at: '2026-10-13T12:59:00Z' },
        budget_seconds: 600,
        stall_seconds: 300,
      },
      undefined,
      now
    )
    expect(n).toEqual({
      kind: 'progress',
      text: '12/72 targets done, last 1m 0s ago, budget 10m 0s',
    })
  })

  it('warns when no target finished for over half the stall window', () => {
    const n = taskProgressNote(
      {
        status: 'running',
        progress: { done: 3, total: 72, last_progress_at: '2026-10-13T12:56:00Z' },
        budget_seconds: 600,
        stall_seconds: 300,
      },
      undefined,
      now
    )
    expect(n?.kind).toBe('stalling')
    expect(n?.text).toBe('No target finished for 4m 0s; taken back as stalled after 5m 0s')
  })

  it('says nothing for a task that is not running or reports nothing', () => {
    expect(
      taskProgressNote({ status: 'completed', budget_seconds: 600 }, undefined, now)
    ).toBeNull()
    expect(taskProgressNote({ status: 'running' }, undefined, now)).toBeNull()
    expect(taskProgressNote({ status: 'running', budget_seconds: 300 }, undefined, now)?.text).toBe(
      'budget 5m 0s'
    )
  })
})
