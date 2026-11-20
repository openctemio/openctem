import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AuditLogPage, { periodSince } from '../page'
import type { AuditLogFilters } from '@/features/organization'

const mockUseAuditLogs = vi.fn()
const runExport = vi.fn().mockResolvedValue(undefined)
let canRead = true

vi.mock('@/features/organization', async (orig) => ({
  ...(await orig<object>()),
  useAuditLogs: (f: AuditLogFilters | undefined) => mockUseAuditLogs(f),
  useAuditExport: () => ({ run: runExport, isExporting: false }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { AuditRead: 'audit:read' },
  useHasPermission: () => canRead,
}))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    pagination: { pageIndex: 0, pageSize: 20 },
    setPagination: vi.fn(),
    setPage: vi.fn(),
  }),
}))

const LOG = {
  id: 'l1',
  action: 'user.login',
  actor_email: 'x@example.com',
  resource_type: 'user',
  resource_id: 'r1',
  result: 'denied',
  severity: 'high',
  timestamp: new Date().toISOString(),
}

const lastFilters = (): AuditLogFilters => mockUseAuditLogs.mock.lastCall?.[0]
const go = (query: string) => window.history.replaceState(null, '', `/settings/audit-log${query}`)

describe('audit log filters', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    canRead = true
    mockUseAuditLogs.mockReturnValue({
      logs: [LOG],
      total: 1284,
      isLoading: false,
      isError: false,
      mutate: vi.fn(),
    })
    go('')
  })

  it('sends no filter at rest: every period, system events shown', () => {
    render(<AuditLogPage />)
    const f = lastFilters()
    expect(f.result).toBeUndefined()
    expect(f.severity).toBeUndefined()
    expect(f.since).toBeUndefined()
    expect(f.exclude_system).toBeUndefined()
    expect(screen.queryByTestId('audit-filter-chips')).toBeNull()
  })

  it('reads every filter from the URL, sends it and shows it as a chip', () => {
    go('?result=failure,denied&severity=high&period=7d&hide_system=true')
    const before = Date.now()
    render(<AuditLogPage />)
    const f = lastFilters()
    expect(f.result).toEqual(['failure', 'denied'])
    expect(f.severity).toEqual(['high'])
    expect(f.exclude_system).toBe(true)
    const since = new Date(f.since!).getTime()
    expect(before - since).toBeGreaterThanOrEqual(7 * 86_400_000 - 1)
    expect(before - since).toBeLessThan(7 * 86_400_000 + 61_000)
    const chips = screen.getByTestId('audit-filter-chips')
    expect(chips).toHaveTextContent('Result: Failure, Denied')
    expect(chips).toHaveTextContent('Severity: High')
    expect(chips).toHaveTextContent('Period: Last 7 days')
    expect(chips).toHaveTextContent('System events hidden')
  })

  it('ignores values it does not know (an old ?result=all link)', () => {
    go('?result=all&severity=bogus&period=forever')
    render(<AuditLogPage />)
    const f = lastFilters()
    expect(f.result).toBeUndefined()
    expect(f.severity).toBeUndefined()
    expect(f.since).toBeUndefined()
  })

  it('removing a chip drops only that filter', async () => {
    go('?result=failure&period=24h')
    const user = userEvent.setup()
    render(<AuditLogPage />)
    await user.click(screen.getByRole('button', { name: 'Remove filter Period: Last 24 hours' }))
    await waitFor(() => expect(lastFilters().since).toBeUndefined())
    expect(lastFilters().result).toEqual(['failure'])
    expect(window.location.search).toBe('?result=failure')
  })

  it('shows the count of matching events once', () => {
    render(<AuditLogPage />)
    expect(screen.getAllByText('1,284')).toHaveLength(1)
  })

  it('names the count and the filters in the export confirmation', async () => {
    go('?period=7d&hide_system=true')
    const user = userEvent.setup()
    render(<AuditLogPage />)
    await user.click(screen.getByRole('button', { name: 'Export' }))
    await user.click(await screen.findByRole('menuitem', { name: 'CSV' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent(
      'This export holds 1,284 events, Last 7 days, System events hidden.'
    )
    expect(runExport).not.toHaveBeenCalled()
  })

  it('fetches nothing and offers no export without the audit permission', () => {
    canRead = false
    render(<AuditLogPage />)
    expect(mockUseAuditLogs).toHaveBeenLastCalledWith(undefined)
    expect(screen.getByText('Access denied')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Export' })).toBeNull()
  })
})

describe('periodSince', () => {
  it('starts the period whole days back, cut to the minute', () => {
    const now = Date.UTC(2026, 10, 20, 10, 48, 31, 500)
    expect(periodSince('24h', now)).toBe('2026-11-19T10:48:00.000Z')
    expect(periodSince('30d', now)).toBe('2026-10-21T10:48:00.000Z')
  })
})
