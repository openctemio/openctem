/**
 * research/22 P0-12: the review queue is reachable and its count is honest.
 * The "Not ours" tab is deep-linkable (?tab=rejected); the Review tab and the
 * sidebar badge show the queue's own total for the awaiting states.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({ can: () => true }),
    useVisibleSectionTabs: <T,>(tabs: readonly T[]) => tabs,
  }
})
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['attack_surface'], isLoading: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))

const { EASMReviewQueue } = await import('../easm-review-queue')
const { useEASMReviewCount } = await import('../../hooks/use-easm-review')

const swr = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

const queueCall = () =>
  api.get.mock.calls.map((c) => c[0] as string).find((u) => u.includes('/easm/candidates?')) ?? ''

beforeEach(() => {
  api.get.mockReset().mockResolvedValue({ total: 7, data: [] })
})
afterEach(() => {
  window.history.replaceState(null, '', '/')
})

describe('review queue reachability', () => {
  it('opens the Not ours tab from ?tab=rejected', async () => {
    window.history.replaceState(null, '', '/attack-surface/review?tab=rejected')
    render(<EASMReviewQueue />, { wrapper: swr })
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(queueCall()).toContain('states=rejected')
    expect(screen.getByRole('tab', { name: 'Not ours' })).toHaveAttribute('data-state', 'active')
  })

  it('falls back to Awaiting review on an unknown tab', async () => {
    window.history.replaceState(null, '', '/attack-surface/review?tab=bogus')
    render(<EASMReviewQueue />, { wrapper: swr })
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(queueCall()).toContain('states=needs_review%2Ccandidate')
  })

  it('counts the awaiting states with the queue query', async () => {
    const { result } = renderHook(() => useEASMReviewCount(true), { wrapper: swr })
    await waitFor(() => expect(result.current).toBe(7))
    expect(api.get).toHaveBeenCalledWith(
      '/api/v1/easm/candidates?states=needs_review%2Ccandidate&page=1&per_page=1'
    )
  })

  it('fetches nothing when disabled', () => {
    renderHook(() => useEASMReviewCount(false), { wrapper: swr })
    expect(api.get).not.toHaveBeenCalled()
  })
})
