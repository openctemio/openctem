import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { post } from '@/lib/api/client'

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
const breadcrumbTitles = vi.hoisted(() => [] as (string | null | undefined)[])
vi.mock('@/features/scans/components', () => ({
  EditScanDialog: ({ open, scanConfig }: { open: boolean; scanConfig: { name: string } }) =>
    open ? <div role="dialog">Editing {scanConfig.name}</div> : null,
  CloneScanDialog: ({ open, scan }: { open: boolean; scan: { name: string } }) =>
    open ? <div role="dialog">Cloning {scan.name}</div> : null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
  useBreadcrumbTitle: (title: string | null | undefined) => breadcrumbTitles.push(title),
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

  // An embedded list keeps its paging local (no prefixed run_page in the
  // URL); "View all runs" links to the Runs list filtered to this scan.
  it('pages the run history on the server and links to the full runs list', async () => {
    render(<ScanDetailPage />)
    expect(runCalls).toContainEqual({ page: 1, perPage: 25 })
    // The numbers come from the newest runs whatever page is open.
    expect(runCalls).toContainEqual({ page: 1, perPage: 10 })
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(runCalls).toContainEqual({ page: 2, perPage: 25 })
    expect(screen.getByText(/^Showing/).textContent).toMatch(/26\s*-\s*50\s*of\s*60\s*runs/)
    expect(Object.keys(urlState).filter((k) => k.startsWith('run_'))).toEqual([])
    expect(screen.getByRole('link', { name: 'View all runs' })).toHaveAttribute(
      'href',
      '/scans/runs?scan_id=s1'
    )
  })

  it('names the scan in the header breadcrumb', () => {
    render(<ScanDetailPage />)
    expect(breadcrumbTitles).toContain('Nightly recon')
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

  it('asks before cancelling a run; only "Cancel run" cancels it', async () => {
    vi.mocked(post).mockClear()
    vi.mocked(post).mockResolvedValue({})
    runsByPage = () => ({
      data: [run('live', { status: 'running', completed_at: undefined })],
      total: 1,
      page: 1,
      per_page: 25,
      total_pages: 1,
    })
    render(<ScanDetailPage />)
    await userEvent.click(screen.getByRole('button', { name: /^Cancel run started/ }))
    expect(post).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Cancel this run of "Nightly recon"?')

    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep running' }))
    expect(post).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: /^Cancel run started/ }))
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel run' })
    )
    expect(post).toHaveBeenCalledTimes(1)
    expect(vi.mocked(post).mock.calls[0][0]).toMatch(/live\/cancel/)
  })

  it('links a workflow scan to its scan workflow', () => {
    urlState.tab = 'details'
    config = { ...config, scan_type: 'workflow', scan_workflow_id: 'wf-1' }
    render(<ScanDetailPage />)
    expect(screen.getByRole('link', { name: 'Open scan workflow' })).toHaveAttribute(
      'href',
      '/scans/workflows/wf-1'
    )
    expect(screen.queryByText('Workflow ID')).toBeNull()
  })

  // The scan page offered no way to edit or clone the scan: only the list's
  // row menu did.
  it('edits and clones the scan from its page', async () => {
    render(<ScanDetailPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Edit' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Editing Nightly recon')
  })

  it('clones the scan from its page', async () => {
    render(<ScanDetailPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Clone' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Cloning Nightly recon')
  })

  // A scan a platform policy owns (continuous coverage): a banner in place of
  // the "no active owner" notice, a System badge and "Automatic coverage"
  // instead of schedule and state, and none of Edit, Run now, schedule or
  // Take ownership. Clone stays and says what it makes.
  describe('a managed scan', () => {
    beforeEach(() => {
      config = {
        ...config,
        name: 'Continuous coverage: probe.http',
        managed_by: 'coverage',
        owner_state: 'managed',
        schedule_type: 'manual',
        ad_hoc: true,
      }
      runsByPage = () => ({
        data: [
          run('r1', {
            status: 'completed',
            trigger_type: 'system',
            triggered_by: 'policy:coverage',
            trigger: { type: 'policy', id: 'coverage' },
            unreachable_target_count: 3,
          }),
        ],
        total: 1,
        page: 1,
        per_page: 25,
        total_pages: 1,
      })
    })

    it('says the platform manages it and links to the coverage settings', () => {
      render(<ScanDetailPage />)
      const banner = screen.getByTestId('managed-scan-banner')
      expect(banner).toHaveTextContent('Managed by the platform · Continuous coverage')
      expect(within(banner).getByRole('link', { name: 'Open coverage settings' })).toHaveAttribute(
        'href',
        '/settings/scope'
      )
      expect(screen.queryByTestId('scan-owner-banner')).toBeNull()
      expect(screen.queryByText('No active owner')).toBeNull()
    })

    it('has no Edit, Run now, schedule switch or Take ownership', () => {
      render(<ScanDetailPage />)
      for (const name of [
        /^Edit$/,
        /Run now/,
        /Take ownership/,
        /Schedule (on|off)/,
        /Delete scan/,
      ]) {
        expect(screen.queryByRole('button', { name })).toBeNull()
      }
      expect(screen.queryByText('Manual')).toBeNull()
    })

    it("shows the System badge and clones as the caller's own scan", async () => {
      render(<ScanDetailPage />)
      expect(screen.getByText('System')).toBeInTheDocument()
      await userEvent.click(screen.getByRole('button', { name: 'Clone as my scan' }))
      expect(screen.getByRole('dialog')).toHaveTextContent(
        'Cloning Continuous coverage: probe.http'
      )
    })

    it('labels a policy run "Automatic coverage" and notes its unreachable targets', () => {
      render(<ScanDetailPage />)
      const row = within(screen.getByRole('table')).getAllByRole('row')[1]
      expect(row).toHaveTextContent('Automatic coverage')
      expect(row).not.toHaveTextContent('System')
      expect(row).toHaveTextContent('Completed')
      expect(row).toHaveTextContent('3 unreachable')
    })
  })
})
