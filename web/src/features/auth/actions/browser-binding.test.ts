import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const jar = new Map<string, { value: string; opts: Record<string, unknown> }>()
const cookieStore = {
  get: vi.fn((name: string) => (jar.has(name) ? { value: jar.get(name)!.value } : undefined)),
  set: vi.fn((name: string, value: string, opts: Record<string, unknown>) => {
    jar.set(name, { value, opts })
  }),
  delete: vi.fn((name: string) => {
    jar.delete(name)
  }),
}
vi.mock('next/headers', () => ({ cookies: vi.fn(async () => cookieStore) }))
vi.mock('next/navigation', () => ({ redirect: vi.fn() }))
vi.mock('@/lib/cookies-server', () => ({ setServerCookie: vi.fn() }))

import { getSSOAuthorizeUrl, handleSSOCallback } from '@/features/sso/actions/sso-auth-actions'
import { bindingCookieName } from '@/features/auth/lib/browser-binding'

import { getOAuthAuthorizationUrl, handleOAuthCallback } from './social-auth-actions'

const authorize = () =>
  new Response(
    JSON.stringify({ authorization_url: 'https://idp/x', state: 'st', browser_binding: 'bind-1' }),
    { status: 200 }
  )

describe('federated sign-in browser binding', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    jar.clear()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    delete process.env.SECURE_COOKIES
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('uses a __Host- cookie when cookies are Secure, plain name over http dev', () => {
    expect(bindingCookieName('sso')).toBe('__Host-sso_binding')
    process.env.SECURE_COOKIES = 'false'
    expect(bindingCookieName('sso')).toBe('sso_binding')
  })

  it.each([
    ['sso', () => getSSOAuthorizeUrl('okta', 'acme')],
    ['oauth', () => getOAuthAuthorizationUrl('google')],
  ] as const)(
    '%s authorize stores the binding HttpOnly, Secure, Lax, path /',
    async (kind, run) => {
      fetchMock.mockResolvedValueOnce(authorize())
      const r = await run()
      expect(r.success).toBe(true)
      const c = jar.get(bindingCookieName(kind))
      expect(c?.value).toBe('bind-1')
      expect(c?.opts).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax', path: '/' })
      expect(c?.opts).not.toHaveProperty('domain')
    }
  )

  it.each([
    ['sso', 'sso_state', () => handleSSOCallback('okta', 'code', 'st')],
    ['oauth', 'oauth_state', () => handleOAuthCallback('google', 'code', 'st')],
  ] as const)(
    '%s callback without the binding cookie never reaches the API',
    async (_k, stateName, run) => {
      jar.set(stateName, { value: 'st', opts: {} })
      const r = await run()
      expect(r.success).toBe(false)
      expect(fetchMock).not.toHaveBeenCalled()
    }
  )

  it.each([
    ['sso', 'sso_state', () => handleSSOCallback('okta', 'code', 'st')],
    ['oauth', 'oauth_state', () => handleOAuthCallback('google', 'code', 'st')],
  ] as const)(
    '%s callback sends the binding and spends the cookie',
    async (kind, stateName, run) => {
      jar.set(stateName, { value: 'st', opts: {} })
      jar.set(bindingCookieName(kind), { value: 'bind-1', opts: {} })
      fetchMock.mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'a' }), { status: 200 })
      )
      await run()
      const body = JSON.parse(fetchMock.mock.calls[0][1].body as string)
      expect(body.browser_binding).toBe('bind-1')
      expect(jar.has(bindingCookieName(kind))).toBe(false)
    }
  )
})
