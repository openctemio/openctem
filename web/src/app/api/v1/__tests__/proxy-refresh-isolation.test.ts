/**
 * @vitest-environment node
 *
 * The API proxy refreshes an expired access token with the caller's own
 * refresh token, and two requests of the same session share one refresh.
 * Requests of different sessions must never share one: the refreshed tokens
 * are set as the caller's cookies, so sharing them hands one person's
 * session to another. The tenant cookie is chosen by the client and is not
 * an identity.
 */
import { AsyncLocalStorage } from 'node:async_hooks'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cookies } from 'next/headers'
import { NextRequest } from 'next/server'

import { GET as v1GET } from '@/app/api/v1/[...path]/route'
import { resetServerRefreshFlights } from '@/lib/server-refresh'

const APP = 'https://app.example.test'
const TENANT = '01a12aa1-8071-74f1-999a-9de298f5b787'
const VICTIM_RT = 'victim-refresh-token'
const ATTACKER_RT = 'attacker-garbage'

type Store = Record<string, string>

// Each request reads its own cookies, as next/headers does per request.
const requestCookies = new AsyncLocalStorage<Store>()

function storeFor(values: Store) {
  return {
    get: (name: string) => (name in values ? { name, value: values[name] } : undefined),
    set: vi.fn(),
    delete: vi.fn(),
  } as unknown as Awaited<ReturnType<typeof cookies>>
}

function call(values: Store) {
  return requestCookies.run(values, () =>
    v1GET(new NextRequest(`${APP}/api/v1/users/me`, { method: 'GET' }), {
      params: Promise.resolve({ path: ['users', 'me'] }),
    })
  )
}

describe('API proxy token refresh', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.mocked(cookies).mockImplementation(async () => storeFor(requestCookies.getStore() ?? {}))
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/api/v1/auth/refresh')) {
        const body = JSON.parse(String(init?.body ?? '{}')) as { refresh_token?: string }
        if (body.refresh_token !== VICTIM_RT) {
          return new Response('{"code":"UNAUTHORIZED"}', { status: 401 })
        }
        // The victim's refresh is slow enough for another request to arrive.
        await new Promise((r) => setTimeout(r, 50))
        return new Response(
          JSON.stringify({
            access_token: 'victim-access-token',
            refresh_token: 'victim-rotated-refresh',
            expires_in: 900,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
      }
      const auth = new Headers(init?.headers).get('authorization') ?? ''
      return new Response(JSON.stringify({ auth }), {
        status: auth ? 200 : 401,
        headers: { 'content-type': 'application/json' },
      })
    })
  })

  afterEach(() => {
    resetServerRefreshFlights()
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('never hands one session the tokens refreshed for another', async () => {
    const tenantCookie = JSON.stringify({ id: TENANT, slug: 't', role: 'member' })
    const victim = call({ refresh_token: VICTIM_RT, app_tenant: tenantCookie })
    // Let the victim's request reach its refresh before the second arrives.
    await new Promise((r) => setTimeout(r, 5))
    // Another person sends any refresh cookie and the victim's tenant id.
    const attacker = call({ refresh_token: ATTACKER_RT, app_tenant: tenantCookie })
    const [v, a] = await Promise.all([victim, attacker])

    expect(v.cookies.get('auth_token')?.value).toBe('victim-access-token')

    const attackerSetCookies = a.headers.getSetCookie().join('\n')
    expect(attackerSetCookies).not.toContain('victim-access-token')
    expect(attackerSetCookies).not.toContain('victim-rotated-refresh')
    expect(await a.text()).not.toContain('victim-access-token')
    expect(a.status).toBe(401)
  })

  it('still shares one refresh between parallel requests of one session', async () => {
    const tenantCookie = JSON.stringify({ id: TENANT, slug: 't', role: 'member' })
    const session = { refresh_token: VICTIM_RT, app_tenant: tenantCookie }
    const [r1, r2] = await Promise.all([call(session), call(session)])
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
    const refreshCalls = fetchMock.mock.calls.filter(([u]) =>
      String(u).endsWith('/api/v1/auth/refresh')
    )
    expect(refreshCalls).toHaveLength(1)
  })

  it('a request that still carries the old cookie after the refresh reuses it', async () => {
    // The production race: the browser sent a request with the old refresh
    // cookie before the first refresh answered; presenting it again would be
    // a reuse and end the session.
    const tenantCookie = JSON.stringify({ id: TENANT, slug: 't', role: 'member' })
    const session = { refresh_token: VICTIM_RT, app_tenant: tenantCookie }
    const first = await call(session)
    const late = await call(session)
    expect(first.status).toBe(200)
    expect(late.status).toBe(200)
    expect(late.cookies.get('auth_token')?.value).toBe('victim-access-token')
    const refreshCalls = fetchMock.mock.calls.filter(([u]) =>
      String(u).endsWith('/api/v1/auth/refresh')
    )
    expect(refreshCalls).toHaveLength(1)
  })
})
