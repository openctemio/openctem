import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'

import { RunTasksTable, taskSensorLabel } from '../run-tasks-table'
import { runOutcomeCallout } from '../run-detail-sheet'

describe('RunTasksTable', () => {
  it('lists each task with its status, tool, sensor, target count and duration', () => {
    render(
      <RunTasksTable
        total={3}
        truncated={false}
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
    expect(screen.queryByText(/Showing the first/)).not.toBeInTheDocument()
  })

  it('says when the list is cut short', () => {
    render(<RunTasksTable total={450} truncated tasks={[{ id: 't1', status: 'running' }]} />)
    expect(screen.getByText('Showing the first 1 of 450 tasks.')).toBeInTheDocument()
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
