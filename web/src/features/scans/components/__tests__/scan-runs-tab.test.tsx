import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ScanRunsTab } from '../scan-runs-tab'

// The Runs tab reads pipeline runs (the table every scan trigger writes),
// paged on the server; it used to read scan sessions, which stayed empty.
const pipelineRunsCalls: Array<Record<string, unknown> | undefined> = []
let runsResponse: unknown
let canReadPipelines = true

vi.mock('@/lib/api/pipeline-hooks', () => ({
  usePipelineRuns: (filters?: Record<string, unknown>) => {
    pipelineRunsCalls.push(filters)
    return { data: runsResponse, isLoading: false, error: undefined }
  },
  useScanManagementStats: () => ({
    data: {
      pipelines: {
        total: 40,
        running: 1,
        pending: 0,
        completed: 4,
        partial: 2,
        failed: 33,
        canceled: 0,
      },
    },
    isLoading: false,
  }),
}))
vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfigs: () => ({ data: { items: [{ id: 's1', name: 'Daily external recon' }] } }),
}))
vi.mock('../run-detail-sheet', () => ({
  RunDetailSheet: ({ runId }: { runId: string | null }) =>
    runId ? <div data-testid="run-sheet">{runId}</div> : null,
}))
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    Can: ({ children, fallback }: { children: React.ReactNode; fallback?: React.ReactNode }) =>
      canReadPipelines ? <>{children}</> : <>{fallback}</>,
  }
})
const urlState: Record<string, string> = {}
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (key: string, fallback: string) => [
    urlState[key] ?? fallback,
    (v: string) => {
      urlState[key] = v
    },
  ],
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const run = (over: Record<string, unknown>) => ({
  id: 'r1',
  tenant_id: 't',
  pipeline_id: 'p',
  scan_id: 's1',
  trigger_type: 'manual',
  triggered_by_name: 'Admin',
  status: 'failed',
  total_steps: 2,
  completed_steps: 1,
  failed_steps: 1,
  skipped_steps: 0,
  total_findings: 0,
  created_at: '2026-10-02T10:00:00Z',
  started_at: '2026-10-02T10:00:00Z',
  completed_at: '2026-10-02T10:03:12Z',
  error_message: 'no sensor online',
  ...over,
})

describe('ScanRunsTab', () => {
  beforeEach(() => {
    pipelineRunsCalls.length = 0
    canReadPipelines = true
    for (const k of Object.keys(urlState)) delete urlState[k]
    runsResponse = {
      items: [
        run({}),
        run({
          id: 'r2',
          scan_id: undefined,
          status: 'running',
          failed_steps: 0,
          completed_at: undefined,
          error_message: undefined,
          total_findings: 7,
        }),
      ],
      total: 40,
      page: 1,
      per_page: 25,
      total_pages: 2,
    }
  })

  it('lists pipeline runs, one page at a time, with the scan name and outcome', () => {
    render(<ScanRunsTab />)
    expect(pipelineRunsCalls.at(-1)).toMatchObject({ page: 1, per_page: 25 })
    expect(pipelineRunsCalls.at(-1)?.status).toBeUndefined()

    const table = screen.getByRole('table')
    expect(within(table).getByRole('link', { name: 'Daily external recon' })).toHaveAttribute(
      'href',
      '/scans/s1'
    )
    expect(within(table).getByText('Pipeline run')).toBeInTheDocument()
    expect(within(table).getByText('no sensor online')).toBeInTheDocument()
    expect(within(table).getByText('(1 failed)')).toBeInTheDocument()
    expect(within(table).getByText('3m 12s')).toBeInTheDocument()
    expect(within(table).getByText(/so far$/)).toBeInTheDocument()
    expect(within(table).getByText('7')).toBeInTheDocument()
  })

  it('shows the real run counts; failed includes timed out and does not filter', () => {
    render(<ScanRunsTab />)
    expect(screen.getByText('Failed or timed out')).toBeInTheDocument()
    expect(screen.getByText('33')).toBeInTheDocument()
  })

  it('counts partial runs and filters on them', async () => {
    render(<ScanRunsTab />)
    await userEvent.click(screen.getByText('Partial'))
    expect(urlState.run_status).toBe('partial')
  })

  it('opens the run drawer on row click', async () => {
    render(<ScanRunsTab />)
    await userEvent.click(screen.getByText('no sensor online'))
    expect(screen.getByTestId('run-sheet')).toHaveTextContent('r1')
  })

  it('passes the status filter to the API', () => {
    urlState.run_status = 'canceled'
    render(<ScanRunsTab />)
    expect(pipelineRunsCalls.at(-1)).toMatchObject({ status: 'canceled', page: 1 })
  })

  it('explains the missing permission instead of showing an empty table', () => {
    canReadPipelines = false
    render(<ScanRunsTab />)
    expect(screen.getByText(/needs the "View pipelines" permission/)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })
})

describe('ScanRunsTab tasks', () => {
  beforeEach(() => {
    canReadPipelines = true
    for (const k of Object.keys(urlState)) delete urlState[k]
  })

  it('shows a run as tasks done of total with the counts that matter', () => {
    runsResponse = {
      items: [
        run({
          status: 'partial',
          error_message: undefined,
          task_summary: {
            total: 5,
            queued: 0,
            running: 0,
            completed: 3,
            failed: 2,
            canceled: 0,
            sensors: 2,
          },
        }),
      ],
      total: 1,
      page: 1,
      per_page: 25,
      total_pages: 1,
    }
    render(<ScanRunsTab />)
    const table = screen.getByRole('table')
    expect(within(table).getByText('3/5 tasks')).toBeInTheDocument()
    expect(within(table).getByText('2 failed')).toBeInTheDocument()
    expect(within(table).getByText('Partial')).toBeInTheDocument()
  })

  it('falls back to steps for a run without a task summary', () => {
    runsResponse = { items: [run({})], total: 1, page: 1, per_page: 25, total_pages: 1 }
    render(<ScanRunsTab />)
    expect(within(screen.getByRole('table')).getByText(/1\/2 steps/)).toBeInTheDocument()
  })
})
