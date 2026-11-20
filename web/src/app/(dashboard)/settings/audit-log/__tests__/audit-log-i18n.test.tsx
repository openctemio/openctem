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
        resource_type: 'sla_policy',
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
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { AuditRead: 'audit:read' },
  useHasPermission: () => true,
}))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    pagination: { pageIndex: 0, pageSize: 20 },
    setPagination: vi.fn(),
    setPage: vi.fn(),
  }),
}))

describe('audit log page in Vietnamese', () => {
  it('renders the title, search, count, filter entry and badges in Vietnamese', () => {
    window.history.replaceState(null, '', '/settings/audit-log?period=7d&hide_system=true')
    render(
      <I18nProvider locale="vi">
        <AuditLogPage />
      </I18nProvider>
    )
    expect(screen.getByRole('heading', { name: 'Nhật ký kiểm toán' })).toBeInTheDocument()
    expect(screen.getByLabelText('Tìm trong nhật ký kiểm toán')).toBeInTheDocument()
    expect(screen.getByText('Thời gian: 7 ngày qua')).toBeInTheDocument()
    expect(screen.getByText('Đã ẩn sự kiện của hệ thống')).toBeInTheDocument()
    expect(screen.getAllByText('Thất bại').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Xuất' })).toBeInTheDocument()
    expect(screen.getAllByText('Chính sách SLA').length).toBeGreaterThan(0)
    expect(screen.queryByText('SLA policy')).toBeNull()
    expect(screen.queryByText('Hide system')).toBeNull()
    expect(screen.queryByText(/events?\b/)).toBeNull()
  })
})
