import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { I18nProvider } from '@/context/i18n-provider'
import BusinessImpactPage from '../page'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/business-impact',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/features/dashboard/hooks/use-dashboard-stats', () => ({
  useDashboardStats: () => ({
    stats: { findings: { bySeverity: { critical: 2, high: 3 }, averageCvss: 7.2, total: 9 } },
    isLoading: false,
  }),
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssetStats: () => ({
    stats: { total: 10, withFindings: 4, highRiskCount: 1, byCriticality: { critical: 2 } },
    isLoading: false,
  }),
}))
vi.mock('@/features/business-units/api/use-business-units', () => ({
  useBusinessUnits: () => ({ data: { data: [], total: 0 }, isLoading: false }),
}))
vi.mock('@/features/crown-jewels/api/use-crown-jewels', () => ({
  useCrownJewels: () => ({ data: { data: [], total: 0 }, isLoading: false }),
}))

describe('Business impact page i18n', () => {
  it('renders in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <BusinessImpactPage />
      </I18nProvider>
    )
    expect(screen.getByRole('heading', { name: 'Tác động kinh doanh' })).toBeInTheDocument()
    expect(screen.getByText('4 có phát hiện')).toBeInTheDocument()
    expect(screen.getByText('Chưa có tài sản trọng yếu')).toBeInTheDocument()
    expect(screen.getByText('Chưa có đơn vị kinh doanh')).toBeInTheDocument()
    expect(screen.getByText('Chưa đánh giá')).toBeInTheDocument()
    expect(screen.queryByText('No crown jewels yet')).toBeNull()
    expect(screen.queryByText('4 with findings')).toBeNull()
    expect(screen.queryByText('Business units')).toBeNull()
  })
})
