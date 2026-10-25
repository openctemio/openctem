/**
 * research/22 P0-12, research/117: the item list is reachable and the count is
 * honest. The "Not ours" state is deep-linkable (?tab=rejected); the Suggestions
 * tab and the sidebar badge count suggestion cards, not rows.
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
const { useEASMSuggestionCount } = await import('../../hooks/use-easm-suggestions')

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
  it('opens the Not ours state from ?tab=rejected', async () => {
    window.history.replaceState(null, '', '/attack-surface/review?tab=rejected')
    render(<EASMReviewQueue />, { wrapper: swr })
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(queueCall()).toContain('states=rejected')
    expect(screen.getByRole('button', { name: 'State: Not ours' })).toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
  })

  it('falls back to Awaiting a decision on an unknown tab', async () => {
    window.history.replaceState(null, '', '/attack-surface/review?tab=bogus')
    render(<EASMReviewQueue />, { wrapper: swr })
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(queueCall()).toContain('states=needs_review%2Ccandidate')
  })

  it('counts suggestion cards, not rows', async () => {
    api.get.mockResolvedValue({ total: 2, cards: [] })
    const { result } = renderHook(() => useEASMSuggestionCount(true), { wrapper: swr })
    await waitFor(() => expect(result.current).toBe(2))
    expect(api.get).toHaveBeenCalledWith('/api/v1/easm/suggestions?view=count')
  })

  it('fetches nothing when disabled', () => {
    renderHook(() => useEASMSuggestionCount(false), { wrapper: swr })
    expect(api.get).not.toHaveBeenCalled()
  })
})
