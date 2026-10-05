import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ScansPage from '../page'

// Scans › Configurations is paged and sorted on the server. It used to fetch
// the API's default first page (20 scans) and page those on the client, so a
// tenant's 21st scan could not be seen and the footer read "of 20".
const configCalls: Array<Record<string, unknown> | undefined> = []
let configsResponse: unknown

vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfigs: (filters?: Record<string, unknown>) => {
    configCalls.push(filters)
    return { data: configsResponse, isLoading: false }
  },
  useScanConfigStats: () => ({
    data: { total: 57, active: 50, paused: 5, disabled: 2 },
    isLoading: false,
  }),
  useBulkActivateScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkPauseScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkDisableScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
  useBulkDeleteScanConfigs: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateScanConfigsCache: vi.fn(),
}))
vi.mock('@/features/scans/components', () => ({
  NewScanDialog: () => null,
  CloneScanDialog: () => null,
  EditScanDialog: () => null,
  QuickScanDialog: () => null,
}))
vi.mock('@/features/scans/components/scan-config-detail-sheet', () => ({
  ScanConfigDetailSheet: () => null,
}))
vi.mock('@/features/scans/components/scan-runs-tab', () => ({ ScanRunsTab: () => null }))
vi.mock('@/features/sensors/components/sensor-opt-in-banner', () => ({
  SensorOptInBanner: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    useHasPermission: () => true,
  }
})
const urlState: Record<string, string> = {}
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (key: string, fallback: string) => [
    urlState[key] ?? fallback,
    (v: string) => {
      if (v === fallback || v === '') delete urlState[key]
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

const scan = (i: number) => ({
  id: `s${i}`,
  name: `Scan ${i}`,
  scan_type: 'single',
  status: 'active',
  schedule_type: 'manual',
  total_runs: i,
  successful_runs: 0,
  failed_runs: 0,
  created_at: '2026-10-01T10:00:00Z',
})

describe('Scans › Configurations', () => {
  beforeEach(() => {
    configCalls.length = 0
    for (const k of Object.keys(urlState)) delete urlState[k]
    configsResponse = {
      items: Array.from({ length: 25 }, (_, i) => scan(i + 26)),
      total: 57,
      page: 2,
      per_page: 25,
      total_pages: 3,
    }
  })

  it('asks the server for one page, sorted, and counts the whole list', () => {
    urlState.page = '2'
    urlState.sort = '-last_run_at'
    render(<ScansPage />)
    expect(configCalls.at(-1)).toMatchObject({ page: 2, per_page: 25, sort: '-last_run_at' })
    // The footer counts the server's total, not the rows on screen.
    expect(screen.getByText(/^Showing/).textContent).toMatch(/26\s*-\s*50\s*of\s*57\s*scans/)
    expect(screen.queryByText('Runs (listed)')).not.toBeInTheDocument()
  })

  it('falls back to the default sort and page size for a stale link', () => {
    urlState.sort = 'success_rate'
    urlState.per_page = '1000'
    render(<ScansPage />)
    expect(configCalls.at(-1)).toMatchObject({ page: 1, per_page: 25, sort: 'name' })
  })

  it('pages through the URL', async () => {
    urlState.page = '2'
    render(<ScansPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(urlState.page).toBe('3')
  })

  it('sorts on the server from a column header and returns to page 1', async () => {
    urlState.page = '2'
    render(<ScansPage />)
    await userEvent.click(screen.getByRole('button', { name: /^Runs/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /Desc/ }))
    expect(urlState.sort).toBe('-total_runs')
    expect(urlState.page).toBeUndefined()
  })
})
