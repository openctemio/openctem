import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

import { RunTaskLogsDialog, logLevelTone, logsEmptyState } from '../run-task-logs-dialog'
import { RunTasksTable } from '../run-tasks-table'

const getMock = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => getMock(...a) }))

const fresh = (ui: React.ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

describe('RunTaskLogsDialog', () => {
  beforeEach(() => getMock.mockReset())

  it('shows each line as plain text with its level, source and collapsed fields', async () => {
    getMock.mockResolvedValue({
      truncated: true,
      lines: [
        {
          ts: '2026-10-05T10:00:00Z',
          level: 'warn',
          msg: '<img src=x onerror=alert(1)> evil\u202eend',
          source: 'nuclei',
          fields: { target: 'https://a.example', n: 3 },
        },
        { ts: '2026-10-05T10:00:01Z', level: 'error', msg: 'failed' },
      ],
    })
    fresh(<RunTaskLogsDialog runId="r 1" taskId="t1" tool="nuclei" open onOpenChange={() => {}} />)

    const list = await screen.findByRole('list', { name: 'Log lines' })
    expect(getMock).toHaveBeenCalledWith('/api/v1/pipeline-runs/r%201/tasks/t1/logs')
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    // Markup in a line is text, never an element; a bidi override is shown as an escape.
    expect(items[0].querySelector('img')).toBeNull()
    expect(items[0]).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(items[0].textContent).not.toContain('\u202e')
    expect(within(items[0]).getByText('warn')).toBeInTheDocument()
    expect(within(items[0]).getByText('nuclei')).toBeInTheDocument()
    expect(within(items[0]).getByText('2 fields')).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent(/not shown/)
  })

  it('says when a task has no logs, and fetches nothing while closed', async () => {
    getMock.mockResolvedValue({ lines: [], truncated: false })
    const { rerender } = fresh(
      <RunTaskLogsDialog runId="r1" taskId="t1" open={false} onOpenChange={() => {}} />
    )
    expect(getMock).not.toHaveBeenCalled()
    rerender(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <RunTaskLogsDialog runId="r1" taskId="t1" open onOpenChange={() => {}} />
      </SWRConfig>
    )
    expect(await screen.findByText('No logs from this task')).toBeInTheDocument()
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
  })

  it('says why a refused task has no logs', async () => {
    getMock.mockResolvedValue({ lines: [], truncated: false })
    const reason =
      'refused by local policy: targets: cannot resolve api.example.com (an address the policy cannot check is refused)'
    fresh(
      <RunTaskLogsDialog
        runId="r1"
        taskId="t1"
        task={{ status: 'failed', error_message: reason }}
        open
        onOpenChange={() => {}}
      />
    )
    expect(await screen.findByText('This task was refused before it ran')).toBeInTheDocument()
    expect(screen.getByText(reason)).toBeInTheDocument()
    expect(screen.queryByText('No logs from this task')).not.toBeInTheDocument()
  })

  it('picks the empty state from the task', () => {
    expect(logsEmptyState(undefined).title).toBe('No logs from this task')
    expect(logsEmptyState({ status: 'completed', error_message: '' }).title).toBe(
      'No logs from this task'
    )
    expect(
      logsEmptyState({
        status: 'failed',
        error_message: 'refused by the managed policy: tools.allow: x',
      }).title
    ).toBe('This task was refused before it ran')
    const failed = logsEmptyState({ status: 'failed', error_message: 'sensor went offline' })
    expect(failed.title).toBe('This task failed before it sent any logs')
    expect(failed.description).toBe('sensor went offline')
    // A queued task handed back by its sensor is waiting, not refused.
    expect(
      logsEmptyState({ status: 'queued', error_message: 'released by sensor: no free slot' }).title
    ).toBe('No logs from this task')
    // Sensor-supplied text: hidden characters are shown as escapes.
    expect(
      logsEmptyState({ status: 'failed', error_message: 'refused by local policy: x\u202ey' })
        .description
    ).not.toContain('\u202e')
  })

  it('maps levels to tones', () => {
    expect(logLevelTone('error')).toBe('destructive')
    expect(logLevelTone('warn')).toBe('warning')
    expect(logLevelTone('debug')).toBe('muted')
    expect(logLevelTone('info')).toBe('info')
    expect(logLevelTone(undefined)).toBe('info')
  })
})

describe('RunTasksTable logs action', () => {
  beforeEach(() => getMock.mockReset())

  it('passes the row status so a refused task says why it has no logs', async () => {
    getMock.mockResolvedValue({ lines: [] })
    fresh(
      <RunTasksTable
        runId="r1"
        total={1}
        tasks={[
          {
            id: 't7',
            status: 'failed',
            tool: 'nuclei',
            targets: 2,
            error_message: 'refused by local policy: targets: 2 target(s) refused',
          },
        ]}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Logs of the nuclei task' }))
    expect(await screen.findByText('This task was refused before it ran')).toBeInTheDocument()
  })

  it('opens the logs of the row it is on', async () => {
    getMock.mockResolvedValue({
      lines: [{ ts: '2026-10-05T10:00:00Z', level: 'info', msg: 'hello' }],
    })
    fresh(
      <RunTasksTable
        runId="r1"
        total={1}
        tasks={[{ id: 't9', status: 'completed', tool: 'httpx', targets: 1 }]}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Logs of the httpx task' }))
    expect(await screen.findByText('hello')).toBeInTheDocument()
    expect(getMock).toHaveBeenCalledWith('/api/v1/pipeline-runs/r1/tasks/t9/logs')
  })
})
