/**
 * The session bootstrap replaces /users/me, /users/me/tenants, the unread
 * count, the review-queue badge and /auth/providers on every page load
 * (research/81). These tests pin that the consumers of those endpoints read
 * the bootstrap's values from the cache and send no request of their own.
 */
import * as React from 'react'
import { cleanup, render, renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { EASM_REVIEW_COUNT_URL, seedSessionCache } from '../bootstrap-session'
import {
  reviewQueueURL,
  REVIEW_QUEUE_STATES,
} from '@/features/attack-surface/hooks/use-easm-review'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...args: unknown[]) => get(...args),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  // A fresh cache per test, the same provider the app uses.
  return <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
}

describe('session bootstrap cache', () => {
  beforeEach(() => get.mockReset())
  afterEach(() => cleanup())

  it('seeds the review badge under the exact key the sidebar reads', () => {
    expect(EASM_REVIEW_COUNT_URL).toBe(
      reviewQueueURL({ states: REVIEW_QUEUE_STATES, page: 1, perPage: 1 })
    )
  })

  it('a seeded profile is read from the cache without a request', async () => {
    const { useProfile } = await import('@/features/account/api/use-profile')
    let profile: unknown
    function Probe() {
      profile = useProfile().profile
      return null
    }
    function Seeded({ children }: { children: React.ReactNode }) {
      const [ready, setReady] = React.useState(false)
      React.useEffect(() => {
        void seedSessionCache({
          user: { id: 'u1', email: 'a@example.test', name: 'A' } as never,
        }).then(() => setReady(true))
      }, [])
      return ready ? <>{children}</> : null
    }
    // Seeding writes the global cache, so render under the default provider.
    render(
      <Seeded>
        <Probe />
      </Seeded>
    )
    await waitFor(() => expect(profile).toMatchObject({ id: 'u1' }))
    expect(get).not.toHaveBeenCalled()
  })

  it('without a seed the profile is fetched as before', async () => {
    const { useProfile } = await import('@/features/account/api/use-profile')
    get.mockResolvedValue({ id: 'u2', email: 'b@example.test', name: 'B' })
    const { result } = renderHook(() => useProfile(), { wrapper })
    await waitFor(() => expect(result.current.profile).toMatchObject({ id: 'u2' }))
    expect(get).toHaveBeenCalledWith('/api/v1/users/me')
  })

  it('skips fields the API left out', async () => {
    await expect(seedSessionCache({})).resolves.toBeUndefined()
    await expect(seedSessionCache({ badges: {} })).resolves.toBeUndefined()
  })
})
