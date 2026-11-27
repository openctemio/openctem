import { describe, it, expect, vi, beforeEach } from 'vitest'
import { configure, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ScansPage from '../page'

// Scans › Configurations is paged and sorted on the server. It used to fetch
// the API's default first page (20 scans) and page those on the client, so a
// tenant's 21st scan could not be seen and the footer read "of 20".
const configCalls: Array<Record<string, unknown> | undefined> = []
let configsResponse: unknown
let readError: unknown
const bulkDisable = vi.hoisted(() => vi.fn())
const bulkActivate = vi.hoisted(() => vi.fn())
const bulkPause = vi.hoisted(() => vi.fn())
const bulkDelete = vi.hoisted(() => vi.fn())
// Permissions the signed-in user lacks in a test (none by default).
const denied = vi.hoisted(() => new Set<string>())

vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfigs: (filters?: Record<string, unknown>) => {
    configCalls.push(filters)
    return { data: configsResponse, isLoading: false, error: readError, mutate: vi.fn() }
  },
  useScanConfigStats: () => ({
    data: { total: 57, active: 50, paused: 5, disabled: 2 },
    isLoading: false,
  }),
  useBulkActivateScanConfigs: () => ({ trigger: bulkActivate, isMutating: false }),
  useBulkPauseScanConfigs: () => ({ trigger: bulkPause, isMutating: false }),
  useBulkDisableScanConfigs: () => ({ trigger: bulkDisable, isMutating: false }),
  useBulkDeleteScanConfigs: () => ({ trigger: bulkDelete, isMutating: false }),
  invalidateScanConfigsCache: vi.fn(),
}))
vi.mock('@/features/scans/components', () => ({
  NewScanDialog: () => null,
  CloneScanDialog: () => null,
  EditScanDialog: () => null,
  QuickScanDialog: () => null,
}))
vi.mock('@/features/scans/components/managed-scans-section', () => ({
  ManagedScansSection: () => null,
}))
vi.mock('@/features/scans/components/scan-config-detail-sheet', () => ({
  ScanConfigDetailSheet: () => null,
}))
vi.mock('@/features/scans/components/scans-section-tabs', () => ({
  ScansPageHeader: () => null,
  ScansSectionTabs: () => null,
  ScanCreateActions: () => null,
}))
vi.mock('@/features/sensors/components/sensor-opt-in-banner', () => ({
  SensorOptInBanner: () => null,
}))
vi.mock('@/features/scan-windows', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/scan-windows')>()),
  ScanWindowsBanner: () => null,
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
    usePermissions: () => ({ can: (p: string) => !denied.has(p) }),
  }
})
// The real URL is the list state (useListParams reads and writes it).
const urlState = new Proxy({} as Record<string, string | undefined>, {
  get: (_, key) => new URLSearchParams(window.location.search).get(String(key)) ?? undefined,
  set: (_, key, value) => {
    const params = new URLSearchParams(window.location.search)
    params.set(String(key), String(value))
    window.history.replaceState(null, '', `/scans?${params}`)
    return true
  },
})
const resetUrl = () => window.history.replaceState(null, '', '/scans')

// Every interaction re-renders the whole 25-row table (row menus, run strips,
// checkboxes): about one second per render under coverage on a 4-core runner.
// The file takes ~26 s for 14 tests on a hosted runner, so a test with five
// interactions has no headroom left under the 5 s default and times out on a
// busier self-hosted runner. The tests are slow, not hung.
configure({ asyncUtilTimeout: 10_000 })
vi.setConfig({ testTimeout: 30_000 })

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
    denied.clear()
    readError = undefined
    resetUrl()
    configsResponse = {
      data: Array.from({ length: 25 }, (_, i) => scan(i + 26)),
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
    expect(screen.getByText(/^Showing/).textContent).toMatch(/26 to 50 of 57\s*scans/)
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
    // One click on the header's sort button sorts by the column, in its
    // kind's first direction (a number: largest first).
    await userEvent.click(screen.getByRole('button', { name: /^Runs/ }))
    expect(urlState.sort).toBe('-total_runs')
    expect(urlState.page).toBeUndefined()
  })

  it('asks before disabling the selected scans, with the count', async () => {
    bulkDisable.mockReset()
    bulkDisable.mockResolvedValue({ message: 'ok' })
    render(<ScansPage />)
    const boxes = screen.getAllByRole('checkbox')
    await userEvent.click(boxes[1])
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Disable' }))
    expect(bulkDisable).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Disable 1 scan?')
    expect(within(dialog).getByText('Scan 26')).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disable 1 scan' }))
    await waitFor(() => expect(bulkDisable).toHaveBeenCalledTimes(1))
    expect(bulkDisable.mock.calls[0][0].scan_ids).toHaveLength(1)
  })

  it('a bulk delete asks to type the count, lists names, and has a counted destructive button', async () => {
    bulkDelete.mockReset()
    bulkDelete.mockResolvedValue({ message: 'ok' })
    render(<ScansPage />)
    await userEvent.click(screen.getAllByRole('checkbox')[0])
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete 25 scans?')
    expect(within(dialog).getByText('Scan 26')).toBeInTheDocument()
    expect(dialog).toHaveTextContent('and 20 more')
    const confirm = within(dialog).getByRole('button', { name: 'Delete 25 scans' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), '25')
    expect(confirm).toBeEnabled()
    expect(bulkDelete).not.toHaveBeenCalled()
    await userEvent.click(confirm)
    await waitFor(() => expect(bulkDelete).toHaveBeenCalledTimes(1))
  })

  it('a bulk delete of one scan asks for its name (not only at ten)', async () => {
    bulkDelete.mockReset()
    render(<ScansPage />)
    await userEvent.click(screen.getAllByRole('checkbox')[1])
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Delete 1 scan' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'Scan 26')
    expect(confirm).toBeEnabled()
  })

  it('a single scan delete from the row menu asks for the scan name', async () => {
    render(<ScansPage />)
    await userEvent.click(screen.getAllByRole('button', { name: /^Actions for / })[0])
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete scan "Scan 26"?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete scan' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), 'Scan 26')
    expect(confirm).toBeEnabled()
  })

  it('Bulk Activate asks with the count and names, then activates', async () => {
    bulkActivate.mockReset()
    bulkActivate.mockResolvedValue({ message: 'ok' })
    render(<ScansPage />)
    await userEvent.click(screen.getAllByRole('checkbox')[0])
    await userEvent.click(screen.getByRole('button', { name: 'Activate' }))
    expect(bulkActivate).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Activate 25 scans?')
    expect(dialog).toHaveTextContent('Scan 26')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Activate 25 scans' }))
    await waitFor(() => expect(bulkActivate).toHaveBeenCalledTimes(1))
    expect(bulkActivate.mock.calls[0][0].scan_ids).toHaveLength(25)
  })

  it('Bulk Pause asks with the count, and Cancel pauses nothing', async () => {
    bulkPause.mockReset()
    render(<ScansPage />)
    await userEvent.click(screen.getAllByRole('checkbox')[1])
    await userEvent.click(screen.getByRole('button', { name: 'Pause' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Pause 1 scan?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(bulkPause).not.toHaveBeenCalled()
  })

  // The platform's managed scans (continuous coverage) are listed apart from
  // people's: the Origin filter sends origin=system / origin=user.
  it("lists the platform's scans under the System origin filter", async () => {
    render(<ScansPage />)
    expect(configCalls.at(-1)?.origin).toBeUndefined()
    await userEvent.click(screen.getByRole('button', { name: 'Origin: All origins' }))
    await userEvent.click(await screen.findByRole('menuitemradio', { name: 'System' }))
    expect(urlState.origin).toBe('system')
    await waitFor(() => expect(configCalls.at(-1)).toMatchObject({ origin: 'system' }))
    await userEvent.click(screen.getByRole('button', { name: 'Origin: System' }))
    await userEvent.click(await screen.findByRole('menuitemradio', { name: 'People' }))
    await waitFor(() => expect(configCalls.at(-1)).toMatchObject({ origin: 'user' }))
  })

  // The list pattern: the bar holds two direct actions, the rest under More.
  it('the bulk bar has Activate and Pause, then Disable and Delete under More', async () => {
    render(<ScansPage />)
    await userEvent.click(screen.getAllByRole('checkbox')[1])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    expect(within(bar).getByRole('button', { name: 'Activate' })).toBeInTheDocument()
    expect(within(bar).getByRole('button', { name: 'Pause' })).toBeInTheDocument()
    expect(within(bar).queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
    expect(within(bar).queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    await userEvent.click(within(bar).getByRole('button', { name: 'More actions' }))
    const items = (await screen.findAllByRole('menuitem')).map((i) => i.textContent)
    expect(items).toEqual(['Disable', 'Delete'])
  })

  it('offers no row selection to a user who can neither change nor delete scans', () => {
    denied.add('scans:write')
    denied.add('scans:delete')
    render(<ScansPage />)
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
  })

  it('without scans:write the bar offers only Delete, under More', async () => {
    denied.add('scans:write')
    render(<ScansPage />)
    await userEvent.click(screen.getAllByRole('checkbox')[1])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    expect(within(bar).queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    await userEvent.click(within(bar).getByRole('button', { name: 'More actions' }))
    expect((await screen.findAllByRole('menuitem')).map((i) => i.textContent)).toEqual(['Delete'])
  })

  // Filters set from Add filter (or a link) show as chips, each removable;
  // State and Origin are the toolbar's own selects and never chips.
  it('shows the type, schedule, tag and one-off filters as removable chips', async () => {
    urlState.type = 'workflow'
    urlState.schedule = 'daily'
    urlState.tag = 'perimeter'
    urlState.one_off = '1'
    urlState.status = 'paused'
    render(<ScansPage />)
    const chips = screen.getAllByTestId('filter-chip').map((c) => c.textContent)
    expect(chips).toEqual([
      'Scan type: Workflow',
      'Schedule: Daily',
      'Tag: perimeter',
      'One-off scans shown',
    ])
    expect(screen.getByRole('button', { name: 'State: Schedule paused' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Remove filter Scan type: Workflow' }))
    expect(urlState.type).toBeUndefined()
    expect(urlState.schedule).toBe('daily')
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(urlState.schedule).toBeUndefined()
    expect(urlState.tag).toBeUndefined()
    expect(urlState.one_off).toBeUndefined()
    // Clear filters removes the chips; the State select keeps its value.
    expect(urlState.status).toBe('paused')
  })

  it('the name is a link to the scan page', () => {
    render(<ScansPage />)
    const link = screen.getByRole('link', { name: 'Scan 26, view details' })
    expect(link).toHaveAttribute('href', '/scans/s26')
  })

  it('says "no match" with Clear filters when a filter leaves no row', async () => {
    urlState.status = 'disabled'
    urlState.q = 'zz'
    configsResponse = { data: [], total: 0, page: 1, per_page: 25, total_pages: 0 }
    render(<ScansPage />)
    expect(screen.getByText('No scans match these filters')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(urlState.status).toBeUndefined()
    expect(urlState.q).toBeUndefined()
  })

  it('says "No scans yet" on an empty, unfiltered list', () => {
    configsResponse = { data: [], total: 0, page: 1, per_page: 25, total_pages: 0 }
    render(<ScansPage />)
    expect(screen.getByText('No scans yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument()
  })

  it('shows the no-access notice, not an error, when the read is refused', () => {
    configsResponse = undefined
    readError = { statusCode: 403, code: 'FORBIDDEN' }
    render(<ScansPage />)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.getByText(/do not have access/i)).toBeInTheDocument()
  })

  it('reads the origin from a shared link', () => {
    urlState.origin = 'system'
    render(<ScansPage />)
    expect(configCalls.at(-1)).toMatchObject({ origin: 'system' })
  })

  it('shows the recent runs and a success rate that does not count coverage gaps as failures', () => {
    const at = '2026-10-20T10:00:00Z'
    configsResponse = {
      data: [
        {
          ...scan(1),
          successful_runs: 1,
          partial_runs: 2,
          failed_runs: 1,
          blocked_runs: 1,
          total_runs: 5,
          recent_runs: [
            {
              id: 'r5',
              status: 'blocked',
              refusal_code: 'ALL_TARGETS_UNCONFIRMED',
              created_at: at,
            },
            { id: 'r4', status: 'partial', created_at: at },
            { id: 'r3', status: 'partial', created_at: at },
            { id: 'r2', status: 'failed', created_at: at },
            { id: 'r1', status: 'completed', created_at: at },
          ],
        },
      ],
      total: 1,
      page: 1,
      per_page: 25,
      total_pages: 1,
    }
    render(<ScansPage />)
    expect(screen.getByRole('columnheader', { name: /Recent runs/ })).toBeInTheDocument()
    // 1 completed + 2 partial of 4 that ran: 75%; the blocked run is not counted.
    const history = screen.getByRole('img', { name: /Success rate 75%/ })
    expect(history.getAttribute('aria-label')).toContain('Blocked before starting: 1, not counted')
    expect(history.getAttribute('aria-label')).toContain('Completed with coverage gaps: 2')
  })

  it('has no success rate below three finished runs', () => {
    configsResponse = {
      data: [
        {
          ...scan(1),
          successful_runs: 1,
          failed_runs: 1,
          total_runs: 2,
          recent_runs: [
            { id: 'r2', status: 'failed', created_at: '2026-10-20T10:00:00Z' },
            { id: 'r1', status: 'completed', created_at: '2026-10-19T10:00:00Z' },
          ],
        },
      ],
      total: 1,
      page: 1,
      per_page: 25,
      total_pages: 1,
    }
    render(<ScansPage />)
    expect(
      screen.getByRole('img', { name: /No success rate until 3 runs have finished/ })
    ).toBeInTheDocument()
  })
})
