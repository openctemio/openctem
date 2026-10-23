/**
 * /exposures: the Closed tile equals the view it opens (resolved + accepted +
 * false positive), and a failed stats read says so instead of showing zeros.
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
  usePathname: () => '/exposures',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))

const stats = vi.fn()
vi.mock('@/features/exposures/hooks', async (orig) => ({
  ...(await orig<typeof import('@/features/exposures/hooks')>()),
  useExposures: () => ({
    exposures: [],
    total: 0,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  useExposureStats: () => stats(),
  useExposureHistory: () => ({ history: [], isLoading: false, error: undefined, mutate: vi.fn() }),
}))

import ExposuresPage from '../page'

const base = {
  total: 20,
  active_count: 5,
  resolved_count: 4,
  by_severity: {},
  by_state: { active: 5, resolved: 4, accepted: 3, false_positive: 2, in_review: 0 },
  by_event_type: {},
}

beforeEach(() => stats.mockReset())

describe('/exposures stats', () => {
  it('Closed tile is resolved + accepted + false positive', () => {
    stats.mockReturnValue({ stats: base, isLoading: false, error: undefined, mutate: vi.fn() })
    render(<ExposuresPage />)
    expect(screen.queryByText('Resolved')).not.toBeInTheDocument()
    const tile = screen.getByRole('button', { name: /Closed/ })
    expect(tile).toHaveTextContent('9')
  })

  it('a failed stats read renders an error state with retry, not zeros', () => {
    stats.mockReturnValue({
      stats: { ...base, total: 0 },
      isLoading: false,
      error: new Error('boom'),
      mutate: vi.fn(),
    })
    render(<ExposuresPage />)
    expect(screen.getByText(/Failed to load exposure statistics/i)).toBeInTheDocument()
  })
})
