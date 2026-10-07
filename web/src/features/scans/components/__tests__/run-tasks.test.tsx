import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

import { RunTasksTable, taskSensorLabel, taskSkippedNote, taskStatusNote } from '../run-tasks-table'
import { runOutcomeCallout } from '../run-detail-sheet'

const getMock = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => getMock(...a) }))

// A fresh SWR cache per test, so pages do not leak between tests.
const fresh = (ui: React.ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

describe('RunTasksTable', () => {
  it('lists each task with its status, tool, sensor, target count and duration', () => {
    render(
      <RunTasksTable
        runId="r1"
        total={3}
        tasks={[
          {
            id: 't1',
            status: 'completed',
            tool: 'nuclei',
            sensor_name: 'edge-1',
            targets: 4,
            started_at: '2026-10-04T10:00:00Z',
            completed_at: '2026-10-04T10:02:05Z',
          },
          {
            id: 't2',
            status: 'failed',
            tool: 'nuclei',
            sensor_name: 'edge-2',
            targets: 1,
            error_message: 'scanner exited 2',
          },
          { id: 't3', status: 'queued', tool: 'naabu', targets: 10 },
        ]}
      />
    )
    const rows = within(screen.getByRole('table')).getAllByRole('row')
    expect(rows).toHaveLength(4)
    expect(within(rows[1]).getByText('Completed')).toBeInTheDocument()
    expect(within(rows[1]).getByText('edge-1')).toBeInTheDocument()
    expect(within(rows[1]).getByText('2m 5s')).toBeInTheDocument()
    expect(within(rows[2]).getByText('scanner exited 2')).toBeInTheDocument()
    expect(within(rows[3]).getByText('Waiting for a sensor')).toBeInTheDocument()
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Load/ })).not.toBeInTheDocument()
  })
})

describe('RunTasksTable paging', () => {
  beforeEach(() => {
    getMock.mockReset()
  })

  it('loads the tasks after the first page with the run cursor, then the next cursor', async () => {
    getMock.mockImplementation(async (url: string) => {
      if (url.includes('cursor=c1')) {
        return {
          data: [
            { id: 't2', status: 'completed' },
            { id: 't3', status: 'failed' },
          ],
          next_cursor: 'c2',
        }
      }
      if (url.includes('cursor=c2')) return { data: [{ id: 't4', status: 'queued' }] }
      throw new Error(`unexpected ${url}`)
    })
    fresh(
      <RunTasksTable
        runId="r1"
        total={4}
        nextCursor="c1"
        tasks={[{ id: 't1', status: 'running' }]}
      />
    )
    expect(screen.getByText('Showing 1 of 4 tasks.')).toBeInTheDocument()
    // Nothing is fetched before the user asks.
    expect(getMock).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: 'Load 3 more' }))
    expect(await screen.findByText('Showing 3 of 4 tasks.')).toBeInTheDocument()
    expect(getMock.mock.calls[0][0]).toBe('/api/v1/pipeline-runs/r1/tasks?cursor=c1&per_page=100')

    await userEvent.click(screen.getByRole('button', { name: 'Load 1 more' }))
    // All tasks shown: the counter and the button go away.
    expect(await screen.findAllByRole('row')).toHaveLength(5)
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument()
    expect(getMock.mock.calls.at(-1)?.[0]).toContain('cursor=c2')
  })

  it('offers no button when the API gave no cursor', () => {
    fresh(<RunTasksTable runId="r1" total={450} tasks={[{ id: 't1', status: 'running' }]} />)
    expect(screen.getByText('Showing 1 of 450 tasks.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Load/ })).not.toBeInTheDocument()
  })
})

describe('taskStatusNote', () => {
  it('explains a task its sensor handed back instead of calling it an error', () => {
    expect(
      taskStatusNote({ status: 'queued', error_message: 'released by sensor: hosts are busy' })
    ).toEqual({ kind: 'waiting', text: 'Handed back: hosts are busy' })
    expect(taskStatusNote({ status: 'queued', error_message: 'released by sensor' })).toEqual({
      kind: 'waiting',
      text: 'Handed back by its sensor',
    })
  })

  it('keeps real errors as errors and says nothing without a message', () => {
    expect(taskStatusNote({ status: 'failed', error_message: 'scanner exited 2' })).toEqual({
      kind: 'error',
      text: 'scanner exited 2',
    })
    // A failed task whose message happens to start like a release is still a failure.
    expect(taskStatusNote({ status: 'failed', error_message: 'released by sensor: x' })?.kind).toBe(
      'error'
    )
    expect(taskStatusNote({ status: 'running' })).toBeNull()
  })

  it('shows the waiting reason on the row', () => {
    fresh(
      <RunTasksTable
        runId="r1"
        total={1}
        tasks={[
          { id: 't1', status: 'queued', error_message: 'released by sensor: hosts are busy' },
        ]}
      />
    )
    expect(screen.getByText('Handed back: hosts are busy')).toBeInTheDocument()
  })
})

describe('taskSensorLabel', () => {
  it('never names a shared platform sensor', () => {
    expect(taskSensorLabel({ platform: true, status: 'running' })).toBe('Platform sensor')
    expect(taskSensorLabel({ status: 'failed' })).toBe('-')
  })
})

describe('runOutcomeCallout', () => {
  it('does not call a partial or canceled run failed', () => {
    expect(runOutcomeCallout('partial').tone).toBe('warning')
    expect(runOutcomeCallout('partial').title).not.toMatch(/failed/i)
    expect(runOutcomeCallout('canceled')).toEqual({ tone: 'info', title: 'Run canceled' })
    expect(runOutcomeCallout('failed')).toEqual({ tone: 'destructive', title: 'Run failed' })
    expect(runOutcomeCallout('timeout').title).toBe('Run timed out')
  })
})

describe('taskSkippedNote', () => {
  it('says how many targets the sensor skipped and why', () => {
    expect(
      taskSkippedNote({
        skipped_targets: [{ target: 'api.example.com', reason: 'unresolvable' }],
        skipped_targets_total: 1,
      })
    ).toBe('Completed with 1 target skipped: api.example.com (does not resolve)')
    expect(
      taskSkippedNote({
        skipped_targets: [
          { target: 'a', reason: 'wildcard_pattern' },
          { target: 'b', reason: 'denied_by_policy' },
          { target: 'c', reason: 'invalid_target' },
          { target: 'd', reason: 'something new' },
        ],
        skipped_targets_total: 9,
      })
    ).toBe(
      "Completed with 9 targets skipped: a (wildcard pattern), b (outside the sensor's policy), c (not a valid target), and 6 more"
    )
    expect(taskSkippedNote({ skipped_targets_total: 2 })).toBe('Completed with 2 targets skipped')
    expect(taskSkippedNote({})).toBeNull()
  })

  it('shows the skipped targets on the row', () => {
    fresh(
      <RunTasksTable
        runId="r1"
        total={1}
        tasks={[
          {
            id: 't1',
            status: 'completed',
            tool: 'nuclei',
            targets: 1,
            skipped_targets: [{ target: 'api.example.com', reason: 'unresolvable' }],
            skipped_targets_total: 1,
          },
        ]}
      />
    )
    expect(
      screen.getByText('Completed with 1 target skipped: api.example.com (does not resolve)')
    ).toBeInTheDocument()
  })
})
