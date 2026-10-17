import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import AuditLogPage from '../page'
import { ApiClientError } from '@/lib/api/error-handler'
import en from '@/lib/i18n/dictionaries/en/auditLog.json'
import vi_ from '@/lib/i18n/dictionaries/vi/auditLog.json'

const mockUseAuditLogs = vi.fn()
const mockUseAuditStats = vi.fn()

vi.mock('@/features/organization', async (orig) => ({
  ...(await orig<object>()),
  useAuditLogs: (f: unknown) => mockUseAuditLogs(f),
  useAuditStats: (enabled?: boolean) => mockUseAuditStats(enabled),
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (k: string) => (en as Record<string, string>)[k] ?? k }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { AuditRead: 'audit:read' },
  useHasPermission: () => true,
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_k: string, d: string) => [d, vi.fn()],
}))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    pagination: { pageIndex: 0, pageSize: 20 },
    setPagination: vi.fn(),
    sorting: [],
    setSorting: vi.fn(),
  }),
}))

const base = { logs: [], total: 0, isLoading: false, mutate: vi.fn() }

describe('AuditLogPage for a restricted data scope', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseAuditStats.mockReturnValue({ stats: undefined, isLoading: false })
  })

  it('shows the access state, not a load failure, on a 403 that names the requirement', () => {
    mockUseAuditLogs.mockReturnValue({
      ...base,
      isError: true,
      error: new ApiClientError('forbidden', 'FORBIDDEN', 403, { required: 'full data access' }),
    })
    render(<AuditLogPage />)
    expect(screen.getByText(en['auditLog.needsFullData.title'])).toBeInTheDocument()
    expect(screen.queryByText('Failed to load audit logs')).not.toBeInTheDocument()
    expect(screen.queryByText('Retry')).not.toBeInTheDocument()
    expect(screen.queryByText('Events (7 days)')).not.toBeInTheDocument()
    expect(mockUseAuditStats).toHaveBeenLastCalledWith(false)
  })

  it('still shows the failure alert for other errors and keeps stats on', () => {
    mockUseAuditLogs.mockReturnValue({
      ...base,
      isError: true,
      error: new ApiClientError('boom', 'INTERNAL', 500),
    })
    render(<AuditLogPage />)
    expect(screen.getByText('Failed to load audit logs')).toBeInTheDocument()
    expect(mockUseAuditStats).toHaveBeenLastCalledWith(true)
  })

  it('has the vi translation for both keys', () => {
    for (const k of Object.keys(en)) expect((vi_ as Record<string, string>)[k]).toBeTruthy()
  })
})
