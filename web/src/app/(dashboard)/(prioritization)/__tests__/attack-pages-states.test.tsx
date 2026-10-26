/**
 * /exposure-chains: a failed read says so (it used to render "No relationship
 * data yet"), and a step outside the viewer's scope renders as a placeholder.
 * The /attack-paths view has its own tests (attack-path-view.test.tsx).
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
  usePathname: () => '/exposure-chains',
  useSearchParams: () => new URLSearchParams(),
}))

const chains = vi.fn()
vi.mock('@/features/attack-surface', async (orig) => ({
  ...(await orig<typeof import('@/features/attack-surface')>()),
  useExposureChains: () => chains(),
}))

import ExposureChainsPage from '../exposure-chains/page'

const apiError = new Error('boom: upstream timeout')

beforeEach(() => {
  chains.mockReset()
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
    // Each chain opens the attack-path view of its target.
    expect(screen.getByTestId('chain-attack-paths-link')).toHaveAttribute(
      'href',
      '/attack-paths?target=t1'
    )
  })
})
