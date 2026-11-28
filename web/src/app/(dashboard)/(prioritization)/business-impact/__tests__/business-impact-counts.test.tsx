import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

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
const statsQueries: unknown[] = []
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssetStats: (q?: unknown) => {
    statsQueries.push(q)
    return {
      stats: { total: 615, withFindings: 4, highRiskCount: 1, byCriticality: { critical: 2 } },
      isLoading: false,
    }
  },
}))
const unit = (id: string, name: string, assets: number, risk: number) => ({
  id,
  name,
  criticality: 'high',
  asset_count: assets,
  finding_count: assets ? 5 : 0,
  critical_finding_count: assets ? 1 : 0,
  avg_risk_score: risk,
})
vi.mock('@/features/business-units/api/use-business-units', () => ({
  useBusinessUnits: () => ({
    data: { data: [unit('b1', 'Payments', 3, 72), unit('b2', 'Legal', 0, 0)], total: 2 },
    isLoading: false,
  }),
}))
vi.mock('@/features/crown-jewels/api/use-crown-jewels', () => ({
  useCrownJewels: () => ({ data: { data: [], total: 0 }, isLoading: false }),
}))

describe('Business impact counts', () => {
  it('counts the assets the inventory lists (its default attribution)', () => {
    render(<BusinessImpactPage />)
    expect(statsQueries.at(-1)).toEqual({ attribution: ['approved'] })
  })

  it('says a unit has no assets instead of "no open risk"', () => {
    render(<BusinessImpactPage />)
    expect(screen.getAllByText('No assets assigned')).toHaveLength(1)
  })
})
