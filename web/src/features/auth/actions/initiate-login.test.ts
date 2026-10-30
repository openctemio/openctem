import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const redirect = vi.fn()
const cookieStore = { get: vi.fn(), set: vi.fn(), delete: vi.fn() }
vi.mock('next/headers', () => ({ cookies: vi.fn(async () => cookieStore) }))
vi.mock('next/navigation', () => ({ redirect: (...a: unknown[]) => redirect(...a) }))
vi.mock('@/lib/cookies-server', () => ({ setServerCookie: vi.fn() }))

import { initiateSSOLogin } from '@/features/sso/actions/sso-auth-actions'

import { initiateSocialLogin } from './social-auth-actions'

const authorize = () =>
  new Response(
    JSON.stringify({
      authorization_url: 'https://accounts.example/auth',
      state: 'st',
      browser_binding: 'bind-1',
    }),
    { status: 200 }
  )

describe('initiate sign-in returns the provider URL instead of redirecting', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    redirect.mockReset()
    cookieStore.set.mockReset()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it.each([
    ['social', () => initiateSocialLogin('google', '/dash')],
    ['sso', () => initiateSSOLogin('okta', 'acme', '/dash')],
  ] as const)(
    '%s: success returns the URL, keeps state cookies, never redirects',
    async (_k, run) => {
      fetchMock.mockResolvedValueOnce(authorize())
      const r = await run()
      expect(r).toEqual({ ok: true, url: 'https://accounts.example/auth' })
      const names = cookieStore.set.mock.calls.map((c) => c[0] as string)
      expect(names.some((n) => n.includes('state'))).toBe(true)
      expect(names.some((n) => n.includes('binding'))).toBe(true)
      expect(redirect).not.toHaveBeenCalled()
    }
  )

  it.each([
    ['social', () => initiateSocialLogin('google')],
    ['sso', () => initiateSSOLogin('okta', 'acme')],
  ] as const)('%s: backend failure returns ok:false without redirecting', async (_k, run) => {
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 500 }))
    expect(await run()).toEqual({ ok: false })
    expect(redirect).not.toHaveBeenCalled()
  })
})
