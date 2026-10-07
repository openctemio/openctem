import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ScanRunsTab } from '../scan-runs-tab'

// The Runs tab reads workflow runs (the table every scan trigger writes),
// paged on the server; it used to read scan sessions, which stayed empty.
const workflowRunsCalls: Array<Record<string, unknown> | undefined> = []
let runsResponse: unknown
let canReadScanRuns = true

vi.mock('@/lib/api/scan-workflow-hooks', () => ({
  useScanRuns: (filters?: Record<string, unknown>) => {
    workflowRunsCalls.push(filters)
    return { data: runsResponse, isLoading: false, error: undefined }
  },
  useScanManagementStats: () => ({
    data: {
      scan_runs: {
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
const exportGet = vi.fn()
vi.mock('@/lib/api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api/client')>()),
  get: (...a: unknown[]) => exportGet(...a),
}))
const exportToCsvMock = vi.fn(() => true)
vi.mock('@/hooks/use-csv-export', () => ({
  exportToCsv: (...a: unknown[]) => exportToCsvMock(...(a as [])),
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
      canReadScanRuns ? <>{children}</> : <>{fallback}</>,
  }
})
// The real URL is the list state (useListParams reads and writes it).
const urlState = new Proxy({} as Record<string, string | undefined>, {
  get: (_, key) => new URLSearchParams(window.location.search).get(String(key)) ?? undefined,
  set: (_, key, value) => {
    const params = new URLSearchParams(window.location.search)
    params.set(String(key), String(value))
    window.history.replaceState(null, '', `/scans/runs?${params}`)
    return true
  },
})
const resetUrl = () => window.history.replaceState(null, '', '/scans/runs')

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const run = (over: Record<string, unknown>) => ({
  id: 'r1',
  tenant_id: 't',
  scan_workflow_id: 'p',
  scan_id: 's1',
  scan_name: 'Daily external recon',
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
    workflowRunsCalls.length = 0
    canReadScanRuns = true
    resetUrl()
    runsResponse = {
      data: [
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

  it('lists workflow runs, one page at a time, with the scan name and outcome', () => {
    render(<ScanRunsTab />)
    expect(workflowRunsCalls.at(-1)).toMatchObject({ page: 1, per_page: 25 })
    expect(workflowRunsCalls.at(-1)?.status).toBeUndefined()

    const table = screen.getByRole('table')
    expect(within(table).getByRole('link', { name: 'Daily external recon' })).toHaveAttribute(
      'href',
      '/scans/s1'
    )
    expect(within(table).getByText('Scan run')).toBeInTheDocument()
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
    expect(urlState.status).toBe('partial')
  })

  it('opens the run drawer on row click', async () => {
    render(<ScanRunsTab />)
    await userEvent.click(screen.getByText('no sensor online'))
    expect(screen.getByTestId('run-sheet')).toHaveTextContent('r1')
  })

  it('passes the status filter to the API', () => {
    urlState.status = 'canceled'
    render(<ScanRunsTab />)
    expect(workflowRunsCalls.at(-1)).toMatchObject({ status: 'canceled', page: 1 })
  })

  it('keeps page, page size and sort in the URL and sends them to the API', async () => {
    urlState.page = '2'
    urlState.sort = '-total_findings'
    render(<ScanRunsTab />)
    expect(workflowRunsCalls.at(-1)).toMatchObject({
      page: 2,
      per_page: 25,
      sort: '-total_findings',
    })
    await userEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(urlState.page).toBeUndefined()
  })

  it('sorts on the server from a column header and returns to page 1', async () => {
    urlState.page = '2'
    render(<ScanRunsTab />)
    await userEvent.click(screen.getByRole('button', { name: /^Started/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /Asc/ }))
    expect(urlState.sort).toBe('started_at')
    expect(urlState.page).toBeUndefined()
  })

  it('narrows to one scan from a link and clears it back to every scan', async () => {
    urlState.scan_id = 's1'
    render(<ScanRunsTab />)
    expect(workflowRunsCalls.at(-1)).toMatchObject({ scan_id: 's1', page: 1 })
    await userEvent.click(screen.getByRole('button', { name: 'Show runs of every scan' }))
    expect(urlState.scan_id).toBeUndefined()
  })

  it('uses plain list parameters, never prefixed ones', async () => {
    render(<ScanRunsTab />)
    await userEvent.click(screen.getByText('Partial'))
    expect(window.location.search).toBe('?status=partial')
  })

  it('falls back to newest first for a stale sort link', () => {
    urlState.sort = 'status'
    render(<ScanRunsTab />)
    expect(workflowRunsCalls.at(-1)).toMatchObject({ sort: '-created_at' })
  })

  it('names a quick-scan run from the server and marks a deleted scan', () => {
    runsResponse = {
      data: [
        run({ id: 'q1', scan_id: 'adhoc', scan_name: 'Quick Scan - 20261004-101010' }),
        run({ id: 'd1', scan_id: 'gone', scan_name: undefined, error_message: undefined }),
      ],
      total: 2,
      page: 1,
      per_page: 25,
      total_pages: 1,
    }
    render(<ScanRunsTab />)
    const table = screen.getByRole('table')
    expect(
      within(table).getByRole('link', { name: 'Quick Scan - 20261004-101010' })
    ).toHaveAttribute('href', '/scans/adhoc')
    expect(within(table).getByText('Deleted scan')).toBeInTheDocument()
  })

  it('exports the list as filtered and sorted, through the same endpoint', async () => {
    urlState.status = 'failed'
    urlState.sort = '-started_at'
    exportGet.mockResolvedValue({ data: [run({})], total: 1, page: 1, per_page: 100 })
    render(<ScanRunsTab />)
    await userEvent.click(screen.getByRole('button', { name: /Export CSV/ }))
    await waitFor(() => expect(exportToCsvMock).toHaveBeenCalled())
    const url = String(exportGet.mock.calls.at(-1)?.[0])
    expect(url).toMatch(/^\/api\/v1\/scan-runs\?/)
    expect(url).toContain('status=failed')
    expect(url).toContain('sort=-started_at')
    expect(exportToCsvMock).toHaveBeenCalled()
  })

  it('explains the missing permission instead of showing an empty table', () => {
    canReadScanRuns = false
    render(<ScanRunsTab />)
    expect(screen.getByText(/needs the "View scans" permission/)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })
})

describe('ScanRunsTab tasks', () => {
  beforeEach(() => {
    canReadScanRuns = true
    resetUrl()
  })

  it('shows a run as tasks done of total with the counts that matter', () => {
    runsResponse = {
      data: [
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
    runsResponse = { data: [run({})], total: 1, page: 1, per_page: 25, total_pages: 1 }
    render(<ScanRunsTab />)
    expect(within(screen.getByRole('table')).getByText(/1\/2 steps/)).toBeInTheDocument()
  })
})
