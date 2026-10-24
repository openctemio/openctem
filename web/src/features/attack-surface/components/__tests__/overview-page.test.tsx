/**
 * research/245 area B, /attack-surface: a tile opens exactly the list it
 * counts (same attribution as the stats), rows link to their asset, the info
 * button is never inside a link, and long names truncate.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'

const stats = vi.hoisted(() => ({
  value: {
    totalAssets: 10,
    internetFacingAssets: 4,
    criticalInternetFacingAssets: 1,
    riskScore: 40,
    totalAssetsChange: 2,
    newlyExposed: 1,
    trendWindowDays: 7,
    assetBreakdown: [],
    exposedServicesList: [
      {
        id: '0198f0e2-1111-7000-8000-000000000001',
        name: 'a-very-long-hostname.example.com',
        type: 'domain',
        exposure: 'public',
        criticality: 'high',
        findingCount: 2,
        lastSeen: '2026-10-01T00:00:00Z',
      },
    ],
    recentChanges: [
      {
        type: 'added',
        assetId: '0198f0e2-2222-7000-8000-000000000002',
        assetName: 'new.example.com',
        assetType: 'domain',
        timestamp: '2026-10-01T00:00:00Z',
      },
      {
        type: 'removed',
        assetName: 'gone.example.com',
        assetType: 'domain',
        timestamp: '2026-10-01T00:00:00Z',
      },
    ],
  },
}))

vi.mock('@/features/attack-surface', () => ({
  AttackSurfaceSectionTabs: () => null,
  EASMDecidePanel: () => null,
  EASMOverview: () => null,
  useAttackSurfaceStats: () => ({ stats: stats.value, isLoading: false, error: undefined }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const { default: Page } = await import('@/app/(dashboard)/(scoping)/attack-surface/page')

describe('attack surface overview', () => {
  it('tiles open their list with the attribution the stats count', () => {
    render(<Page />)
    const total = screen.getByRole('link', { name: /^Total assets/ })
    expect(total).toHaveAttribute('href', '/assets?attribution=attributed')
    const facing = screen.getByRole('link', { name: /^Internet-facing assets/ })
    expect(facing).toHaveAttribute('href', '/assets?internet_facing=true&attribution=attributed')
    expect(screen.getByRole('link', { name: /^Critical internet-facing assets/ })).toHaveAttribute(
      'href',
      '/assets?internet_facing=true&criticalities=critical,high&attribution=attributed'
    )
  })

  it('never nests a button inside a tile link', () => {
    render(<Page />)
    const tile = screen.getByRole('link', { name: /^Total assets/ })
    expect(within(tile).queryByRole('button')).toBeNull()
  })

  it('rows link to the asset when the id is known and truncate long names', () => {
    render(<Page />)
    const exposed = screen.getByRole('link', { name: 'a-very-long-hostname.example.com' })
    expect(exposed).toHaveAttribute('href', '/assets/0198f0e2-1111-7000-8000-000000000001')
    expect(exposed.className).toContain('min-w-0')
    expect(exposed.className).toContain('truncate')
    expect(screen.getByRole('link', { name: 'new.example.com' })).toHaveAttribute(
      'href',
      '/assets/0198f0e2-2222-7000-8000-000000000002'
    )
    expect(screen.queryByRole('link', { name: 'gone.example.com' })).toBeNull()
    expect(screen.getByText('gone.example.com')).toBeInTheDocument()
    expect(within(exposed.parentElement as HTMLElement).queryByText(/^:/)).toBeNull()
  })
})
