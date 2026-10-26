import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'
import AuditLogPage from '../page'

vi.mock('@/features/organization', async (orig) => ({
  ...(await orig<object>()),
  useAuditLogs: () => ({
    logs: [
      {
        id: 'l1',
        action: 'user.login',
        actor_email: 'x@y.co',
        resource_type: 'user',
        resource_id: 'r1',
        result: 'failure',
        severity: 'high',
        timestamp: new Date().toISOString(),
      },
    ],
    total: 1,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useAuditStats: () => ({ stats: undefined, isLoading: false }),
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
    setPage: vi.fn(),
  }),
}))

describe('audit log page in Vietnamese', () => {
  it('renders labels, filters and badges in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <AuditLogPage />
      </I18nProvider>
    )
    expect(screen.getByRole('heading', { name: 'Nhật ký kiểm tra' })).toBeInTheDocument()
    expect(screen.getByLabelText('Tìm trong nhật ký kiểm tra')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Kết quả' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Mức độ nghiêm trọng' })).toBeInTheDocument()
    expect(screen.getAllByText('7 ngày qua')).toHaveLength(2)
    expect(
      screen.getByText('Thất bại', {
        selector: '[class*=badge], div, span:not([data-slot="metric-label"])',
      })
    ).toBeInTheDocument()
    expect(screen.queryByText('Events (7 days)')).toBeNull()
    expect(screen.queryByText('Hide system')).toBeNull()
  })
})
