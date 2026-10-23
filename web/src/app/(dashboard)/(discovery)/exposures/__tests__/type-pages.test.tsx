/**
 * The four exposure type pages: a failed stats read renders an error state with
 * retry (it used to read as "no data yet"), and each page asks for its own
 * source set.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/exposures',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/features/dashboard/hooks/use-dashboard-stats', () => ({
  useDashboardStats: () => ({
    stats: { assets: { total: 0, byType: {} }, findingTrend: [] },
    isLoading: false,
  }),
}))
vi.mock('@/features/vulnerabilities', () => ({
  ActiveCVEsTab: () => null,
  VulnerabilityCatalogTab: () => null,
}))

const typeStats = vi.fn()
const sourcesSeen: string[][] = []
vi.mock('@/features/exposures/hooks', async (orig) => ({
  ...(await orig<typeof import('@/features/exposures/hooks')>()),
  useFindingTypeStats: (_tenant: string | null, sources: string[]) => {
    sourcesSeen.push(sources)
    return typeStats()
  },
}))

import VulnerabilitiesPage from '../vulnerabilities/page'
import CodePage from '../code/page'
import MisconfigurationsPage from '../misconfigurations/page'
import SecretsPage from '../secrets/page'

const failed = (mutate = vi.fn()) => ({
  stats: {
    total: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byStatus: {},
    openCount: 0,
    riskScore: 0,
    scoped: true,
  },
  isLoading: false,
  error: new Error('boom'),
  mutate,
})

beforeEach(() => {
  typeStats.mockReset()
  sourcesSeen.length = 0
})

describe.each([
  ['vulnerabilities', VulnerabilitiesPage, /Failed to load vulnerability statistics/i, 'va'],
  ['code', CodePage, /Failed to load code weakness statistics/i, 'sast'],
  [
    'misconfigurations',
    MisconfigurationsPage,
    /Failed to load misconfiguration statistics/i,
    'cspm',
  ],
  ['secrets', SecretsPage, /Failed to load secret statistics/i, 'secret'],
])('/exposures/%s', (_name, Page, title, source) => {
  it('shows an error state with retry, not the empty state', async () => {
    const mutate = vi.fn()
    typeStats.mockReturnValue(failed(mutate))
    render(<Page />)
    expect(screen.getByText(title)).toBeInTheDocument()
    expect(screen.queryByText(/yet/i)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /retry|try again/i }))
    expect(mutate).toHaveBeenCalled()
  })

  it('asks for its own source set', () => {
    typeStats.mockReturnValue(failed())
    render(<Page />)
    expect(sourcesSeen.some((s) => s.includes(source))).toBe(true)
  })
})
