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

import { EASM_SUGGESTIONS_COUNT_URL, seedSessionCache } from '../bootstrap-session'

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

  it('seeds the attack surface badge under the key the sidebar and tab read', () => {
    // One per suggestion card, never one per review row (research/117).
    expect(EASM_SUGGESTIONS_COUNT_URL).toBe('/api/v1/easm/suggestions?view=count')
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

  it('seeded announcements render in the banner without a request', async () => {
    const { PlatformAnnouncementBanner } =
      await import('@/features/announcements/components/platform-announcement-banner')
    function Seeded({ children }: { children: React.ReactNode }) {
      const [ready, setReady] = React.useState(false)
      React.useEffect(() => {
        void seedSessionCache({
          announcements: [
            { id: 'n1', message: 'Maintenance tonight', severity: 'maintenance', starts_at: '' },
          ],
        }).then(() => setReady(true))
      }, [])
      return ready ? <>{children}</> : null
    }
    const { findByText } = render(
      <Seeded>
        <PlatformAnnouncementBanner />
      </Seeded>
    )
    expect(await findByText('Maintenance tonight')).toBeTruthy()
    expect(get).not.toHaveBeenCalled()
  })

  it('seeded sidebar pins are read from the cache without a request', async () => {
    vi.doMock('@/context/tenant-provider', () => ({ useCurrentTenantId: () => 't1' }))
    const { useNavPins } = await import('@/features/nav-pins/api/use-nav-pins')
    let pins: unknown
    function Probe() {
      pins = useNavPins().pins
      return null
    }
    function Seeded({ children }: { children: React.ReactNode }) {
      const [ready, setReady] = React.useState(false)
      React.useEffect(() => {
        void seedSessionCache({
          pins: {
            data: [{ kind: 'quick_view', ref: 'sla_breached', params: 'sla=breached', count: 3 }],
            max: 12,
            include_informational: false,
          },
        }).then(() => setReady(true))
      }, [])
      return ready ? <>{children}</> : null
    }
    render(
      <Seeded>
        <Probe />
      </Seeded>
    )
    await waitFor(() => expect(pins).toMatchObject([{ ref: 'sla_breached', count: 3 }]))
    expect(get).not.toHaveBeenCalled()
    vi.doUnmock('@/context/tenant-provider')
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
