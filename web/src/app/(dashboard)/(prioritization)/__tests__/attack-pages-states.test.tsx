/**
 * /attack-paths and /exposure-chains: a failed read says so (it used to render
 * "No relationship data yet"), the false "breaks the most attack paths" claim
 * is gone, the ranked list shows no invented Internet node, and a step outside
 * the viewer's scope renders as a placeholder.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/attack-paths',
  useSearchParams: () => new URLSearchParams(),
}))

const scoring = vi.fn()
const chains = vi.fn()
vi.mock('@/features/attack-surface', async (orig) => ({
  ...(await orig<typeof import('@/features/attack-surface')>()),
  useAttackPathScoring: () => scoring(),
  useExposureChains: () => chains(),
}))

import AttackPathsPage from '../attack-paths/page'
import ExposureChainsPage from '../exposure-chains/page'

const apiError = new Error('boom: upstream timeout')

beforeEach(() => {
  scoring.mockReset()
  chains.mockReset()
})

describe('/attack-paths', () => {
  it('shows an error state, not the empty state, when the read fails', () => {
    scoring.mockReturnValue({
      scoring: undefined,
      error: apiError,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByText(/Failed to load attack paths/i)).toBeInTheDocument()
    expect(screen.queryByText(/No relationship data yet/i)).not.toBeInTheDocument()
  })

  it('shows the empty state when the read succeeds with no relationships', () => {
    scoring.mockReturnValue({
      scoring: { summary: { hasRelationshipData: false }, topAssets: [] },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByText(/No relationship data yet/i)).toBeInTheDocument()
  })

  it('does not claim a fix breaks the most paths and shows no invented Internet node', () => {
    scoring.mockReturnValue({
      scoring: {
        summary: {
          hasRelationshipData: true,
          totalPaths: 3,
          entryPoints: 1,
          reachableAssets: 1,
          maxDepth: 1,
          criticalReachable: 1,
          crownJewelsAtRisk: 0,
        },
        topAssets: [
          {
            assetId: 'a1',
            name: 'billing-db',
            assetType: 'host',
            exposure: 'private',
            criticality: 'critical',
            riskScore: 8,
            isCrownJewel: false,
            findingCount: 2,
            reachableFrom: 3,
            pathScore: 90,
            isEntryPoint: false,
            isProtected: false,
          },
        ],
      },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<AttackPathsPage />)
    expect(screen.getByText('billing-db')).toBeInTheDocument()
    expect(screen.queryByText(/breaks the most attack paths/i)).not.toBeInTheDocument()
    expect(screen.queryByText('Internet-facing entry points')).not.toBeInTheDocument()
    expect(screen.getByText(/does not tell you which single fix/i)).toBeInTheDocument()
  })
})

describe('/exposure-chains', () => {
  it('shows an error state, not the empty state, when the read fails', () => {
    chains.mockReturnValue({
      chains: undefined,
      error: apiError,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<ExposureChainsPage />)
    expect(screen.getByText(/Failed to load exposure chains/i)).toBeInTheDocument()
    expect(screen.queryByText(/No relationship data yet/i)).not.toBeInTheDocument()
  })

  it('renders a step outside the viewer scope as a placeholder without a name', () => {
    const hop = (id: string, name: string) => ({
      hidden: false,
      assetId: id,
      name,
      assetType: 'host',
      exposure: 'private',
    })
    chains.mockReturnValue({
      chains: {
        summary: { entryPoints: 1, targetsAtRisk: 1, totalChains: 1, hasRelationshipData: true },
        chains: [
          {
            entryPointId: '',
            entryPointName: '',
            targetId: 't1',
            targetName: 'my-crown-jewel',
            targetCriticality: 'critical',
            isCrownJewel: true,
            hops: [
              { hidden: true, assetId: '', name: '', assetType: '', exposure: '' },
              { hidden: true, assetId: '', name: '', assetType: '', exposure: '' },
              hop('t1', 'my-crown-jewel'),
            ],
            length: 2,
            kevCount: 1,
            criticalCount: 0,
            score: 10,
          },
        ],
      },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    })
    render(<ExposureChainsPage />)
    expect(screen.getAllByText('Outside your access')).toHaveLength(2)
    expect(screen.getByText('my-crown-jewel')).toBeInTheDocument()
    // Only the visible asset is a link.
    expect(screen.getAllByRole('link', { name: /my-crown-jewel/i })).toHaveLength(1)
  })
})
