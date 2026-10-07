import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ScanDetailPage from '../page'

// The scan page: run history paged on the server (it stopped at the ten
// newest runs), one metric strip with honest numbers, and targets shown as
// inert, escaped text.
const runCalls: Array<{ page: number; perPage: number }> = []
let config: Record<string, unknown>
let runsByPage: (page: number) => unknown

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 's1' }),
  useRouter: () => ({ push: vi.fn() }),
}))
vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfig: () => ({ data: config, isLoading: false, error: undefined }),
  useScanRuns: (_id: string, page: number, perPage: number) => {
    runCalls.push({ page, perPage })
    return { data: runsByPage(page), isLoading: false, mutate: vi.fn() }
  },
  invalidateScanConfigsCache: vi.fn(),
}))
vi.mock('@/lib/api/security-hooks', () => ({
  useAssetGroup: (id: string) => ({ data: id === 'g1' ? { name: 'Internet edge' } : undefined }),
}))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 'tenant-1' } }),
}))
vi.mock('@/features/scans/components/run-detail-sheet', () => ({
  RunDetailSheet: ({ runId }: { runId: string | null }) =>
    runId ? <div data-testid="run-sheet">{runId}</div> : null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return { ...actual, Can: ({ children }: { children: React.ReactNode }) => <>{children}</> }
})
const urlState: Record<string, string> = {}
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (key: string, fallback: string) => [
    urlState[key] ?? fallback,
    (v: string) => {
      if (v === fallback) delete urlState[key]
      else urlState[key] = v
    },
  ],
  useUrlFilterNumber: (key: string, fallback: number) => [
    urlState[key] ? Number(urlState[key]) : fallback,
    (v: number) => {
      if (v === fallback) delete urlState[key]
      else urlState[key] = String(v)
    },
  ],
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const run = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  status: 'completed',
  trigger_type: 'manual',
  total_steps: 1,
  completed_steps: 1,
  failed_steps: 0,
  skipped_steps: 0,
  total_findings: 2,
  created_at: '2026-10-03T10:00:00Z',
  started_at: '2026-10-03T10:00:00Z',
  completed_at: '2026-10-03T10:01:00Z',
  ...over,
})

describe('Scan page', () => {
  beforeEach(() => {
    runCalls.length = 0
    for (const k of Object.keys(urlState)) delete urlState[k]
    config = {
      id: 's1',
      name: 'Nightly recon',
      status: 'active',
      scan_type: 'single',
      schedule_type: 'daily',
      schedule_timezone: 'UTC',
      sensor_preference: 'auto',
      targets_per_job: 10,
      total_runs: 60,
      successful_runs: 0,
      failed_runs: 0,
      partial_runs: 0,
      asset_group_ids: ['g1'],
      targets: [`evil.com${String.fromCodePoint(0x202e)}moc.knab`],
      created_at: '2026-09-01T10:00:00Z',
    }
    runsByPage = (page) => ({
      data: [run(`p${page}-a`), run(`p${page}-b`)],
      total: 60,
      page,
      per_page: 25,
      total_pages: 3,
    })
  })

  it('pages the run history on the server, with the page in the URL', async () => {
    urlState.run_page = '2'
    render(<ScanDetailPage />)
    expect(runCalls).toContainEqual({ page: 2, perPage: 25 })
    // The numbers come from the newest runs whatever page is open.
    expect(runCalls).toContainEqual({ page: 1, perPage: 10 })
    expect(screen.getByText(/^Showing/).textContent).toMatch(/26\s*-\s*50\s*of\s*60\s*runs/)
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(urlState.run_page).toBe('3')
  })

  it('opens a run in the drawer', async () => {
    render(<ScanDetailPage />)
    const rows = within(screen.getByRole('table')).getAllByRole('row')
    await userEvent.click(within(rows[1]).getAllByRole('cell')[0])
    expect(screen.getByTestId('run-sheet')).toHaveTextContent('p1-a')
  })

  it('says n/a, not 0 %, before any run settled', () => {
    render(<ScanDetailPage />)
    expect(screen.getByText('n/a')).toBeInTheDocument()
    expect(screen.getByText('No finished run yet')).toBeInTheDocument()
  })

  it('shows asset groups by name and targets as escaped text', async () => {
    urlState.tab = 'configuration'
    render(<ScanDetailPage />)
    expect(screen.getByText('Internet edge')).toBeInTheDocument()
    expect(screen.getByLabelText('Target: evil.com\\u{202E}moc.knab')).toBeInTheDocument()
  })

  it('marks a run in progress next to the title and opens it', async () => {
    runsByPage = () => ({
      data: [run('live', { status: 'running', completed_at: undefined })],
      total: 1,
      page: 1,
      per_page: 25,
      total_pages: 1,
    })
    render(<ScanDetailPage />)
    await userEvent.click(screen.getByRole('button', { name: /A run is in progress/ }))
    expect(screen.getByTestId('run-sheet')).toHaveTextContent('live')
  })

  it('links a workflow scan to its scan workflow', () => {
    urlState.tab = 'details'
    config = { ...config, scan_type: 'workflow', scan_workflow_id: 'wf-1' }
    render(<ScanDetailPage />)
    expect(screen.getByRole('link', { name: 'Open scan workflow' })).toHaveAttribute(
      'href',
      '/pipelines/wf-1/builder'
    )
    expect(screen.queryByText('Pipeline ID')).toBeNull()
  })
})
