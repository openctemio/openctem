/**
 * /attack-surface overview (research/353 D3, D4): five tiles, each opening
 * exactly the list it counts (same attribution as the stats), rows open their
 * asset, the info button is never inside a link, long names truncate, and
 * settings and decision cards live in their own views.
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
    assetBreakdown: [] as { type: string; total: number; exposed: number }[],
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
  EASMPostureCard: () => null,
  EASMOverview: () => <div data-testid="middle-row" />,
  useAttackSurfaceStats: () => ({ stats: stats.value, isLoading: false, error: undefined }),
}))
vi.mock('@/features/attack-surface/hooks/use-easm-summary', () => ({
  useEASMSummary: () => ({
    summary: {
      attribution: { needs_review: 3, candidate: 1 },
      new: { last_7_days: 5 },
      exposures: { open: 7 },
    },
    isLoading: false,
  }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const { default: Page } = await import('@/app/(dashboard)/(scoping)/attack-surface/page')

describe('attack surface overview', () => {
  it('has one strip of five tiles, each opening the list it counts', () => {
    render(<Page />)
    const strip = document.querySelector('[data-slot=metric-strip]') as HTMLElement
    const tiles = within(strip).getAllByRole('link')
    expect(tiles).toHaveLength(5)
    expect(screen.getByRole('link', { name: /^Surface assets/ })).toHaveAttribute(
      'href',
      '/assets?attribution=attributed'
    )
    expect(screen.getByRole('link', { name: /^Internet-facing assets/ })).toHaveAttribute(
      'href',
      '/assets?internet_facing=true&attribution=attributed'
    )
    expect(screen.getByRole('link', { name: /^New in the last 7 days/ })).toHaveAttribute(
      'href',
      '/attack-surface/changes'
    )
    expect(screen.getByRole('link', { name: /^Open exposures/ })).toHaveAttribute(
      'href',
      '/exposures'
    )
    const waiting = screen.getByRole('link', { name: /^Waiting for a decision/ })
    expect(waiting).toHaveAttribute('href', '/attack-surface/review')
    expect(waiting.textContent).toContain('4')
  })

  it('never nests a button inside a tile link', () => {
    render(<Page />)
    const tile = screen.getByRole('link', { name: /^Surface assets/ })
    expect(within(tile).queryByRole('button')).toBeNull()
  })

  it('keeps the monitoring settings and the decision cards off the overview', () => {
    render(<Page />)
    expect(screen.queryByRole('switch')).toBeNull()
    expect(screen.queryByText(/name rules waiting/)).toBeNull()
  })

  it('breakdown rows open the inventory of that type', () => {
    stats.value = {
      ...stats.value,
      assetBreakdown: [{ type: 'subdomain', total: 12, exposed: 9 }],
    } as typeof stats.value
    render(<Page />)
    expect(screen.getByRole('link', { name: /Subdomains/ })).toHaveAttribute(
      'href',
      '/assets?types=subdomain&attribution=attributed'
    )
  })

  it('change rows open the asset when the id is known and truncate long names', () => {
    render(<Page />)
    const added = screen.getByRole('link', { name: 'new.example.com' })
    expect(added).toHaveAttribute('href', '/assets/0198f0e2-2222-7000-8000-000000000002')
    expect(added.className).toContain('truncate')
    expect(screen.queryByRole('link', { name: 'gone.example.com' })).toBeNull()
    expect(screen.getByText('gone.example.com')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View all' })).toHaveAttribute(
      'href',
      '/attack-surface/changes'
    )
  })
})
