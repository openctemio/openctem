import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('next/navigation', () => ({
  redirect: (url: string) => {
    throw Object.assign(new Error('NEXT_REDIRECT'), { url })
  },
}))
const jar = new Map<string, string>()
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: vi.fn((name: string) => (jar.has(name) ? { value: jar.get(name) } : undefined)),
    set: vi.fn(),
    delete: vi.fn(),
  })),
  headers: vi.fn(async () => new Headers()),
}))
vi.mock('@/lib/cookies-server', () => ({
  setServerCookie: vi.fn(),
  removeServerCookie: vi.fn(async () => undefined),
}))

import { env } from '@/lib/env'
import { localLogoutAction } from './local-auth-actions'

async function signOut() {
  await expect(localLogoutAction()).rejects.toThrow('NEXT_REDIRECT')
}

// Sign-out ends the API session even after the 15-minute access token has
// expired: the refresh token, which outlives it, is sent in the body.
describe('localLogoutAction ends the server session', () => {
  afterEach(() => {
    jar.clear()
    vi.unstubAllGlobals()
  })

  it('sends the refresh token when the access token cookie is gone', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    jar.set(env.auth.refreshCookieName, 'refresh-abc')

    await signOut()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toContain('/api/v1/auth/logout')
    expect(JSON.parse(String(init.body))).toEqual({ refresh_token: 'refresh-abc' })
  })

  it('makes no call when there is no session cookie at all', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await signOut()

    expect(fetchMock).not.toHaveBeenCalled()
  })
})
