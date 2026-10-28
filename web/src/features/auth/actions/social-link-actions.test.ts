import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const jar = new Map<string, string>()
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (k: string) => (jar.has(k) ? { value: jar.get(k) } : undefined),
    set: (k: string, v: string) => jar.set(k, v),
    delete: (k: string) => jar.delete(k),
  })),
}))
vi.mock('next/navigation', () => ({ redirect: vi.fn() }))
const setServerCookie = vi.fn()
vi.mock('@/lib/cookies-server', () => ({
  setServerCookie: (...a: unknown[]) => setServerCookie(...a),
}))
vi.mock('@/lib/api/browser-context-headers', () => ({ browserContextHeaders: async () => ({}) }))

import { env } from '@/lib/env'
import { bindingCookieName } from '@/features/auth/lib/browser-binding'

import { completeLinkCallback, handleOAuthCallback, rememberLinkState } from './social-auth-actions'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('social sign-in to a linked password account', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    jar.clear()
    fetchMock.mockReset()
    setServerCookie.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('keeps the second-factor challenge in an httpOnly cookie and issues no session', async () => {
    jar.set('oauth_state', 'st')
    jar.set(bindingCookieName('oauth'), 'bind')
    fetchMock.mockResolvedValue(
      json({ mfa_required: true, mfa_token: 'challenge', mfa_purpose: 'verify', expires_in: 300 })
    )
    const r = await handleOAuthCallback('google', 'code', 'st')
    expect(r).toEqual({ success: true, mfaRequired: true, mfaPurpose: 'verify' })
    expect(setServerCookie).toHaveBeenCalledTimes(1)
    const [name, value, opts] = setServerCookie.mock.calls[0]
    expect(name).toBe('mfa_challenge')
    expect(value).toBe('challenge')
    expect(opts).toMatchObject({ httpOnly: true, sameSite: 'strict' })
  })

  it('refuses a second step it does not know', async () => {
    jar.set('oauth_state', 'st')
    jar.set(bindingCookieName('oauth'), 'bind')
    fetchMock.mockResolvedValue(
      json({ mfa_required: true, mfa_token: 'x', mfa_purpose: 'skip', expires_in: 300 })
    )
    const r = await handleOAuthCallback('google', 'code', 'st')
    expect(r.success).toBe(false)
    expect(setServerCookie).not.toHaveBeenCalled()
  })

  it('maps the 409 to its code', async () => {
    jar.set('oauth_state', 'st')
    jar.set(bindingCookieName('oauth'), 'bind')
    fetchMock.mockResolvedValue(json({ code: 'OAUTH_ACCOUNT_EXISTS', message: 'm' }, 409))
    const r = await handleOAuthCallback('google', 'code', 'st')
    expect(r).toMatchObject({ success: false, code: 'OAUTH_ACCOUNT_EXISTS' })
  })
})

describe('linking a provider to the signed-in account', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    jar.clear()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('keeps the state and the link intent, for a known provider only', async () => {
    expect(await rememberLinkState('google', 'st')).toEqual({ success: true })
    expect(jar.get('oauth_state')).toBe('st')
    expect(jar.get('oauth_link_intent')).toBe('google')
    jar.clear()
    expect(await rememberLinkState('evil' as never, 'st')).toEqual({ success: false })
    expect(jar.size).toBe(0)
  })

  it('a callback whose state is not the one kept never reaches the API', async () => {
    jar.set('oauth_state', 'kept')
    jar.set(env.auth.cookieName, 'access')
    const r = await completeLinkCallback('google', 'code', 'forged')
    expect(r).toEqual({ success: false, code: 'OAUTH_INVALID_STATE' })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(jar.has('oauth_state')).toBe(false)
  })

  it('sends the code with the session of the cookie', async () => {
    jar.set('oauth_state', 'st')
    jar.set(bindingCookieName('oauth'), 'bind')
    jar.set('oauth_link_intent', 'google')
    jar.set(env.auth.cookieName, 'access')
    fetchMock.mockResolvedValue(json({ id: 'i', provider: 'google' }))
    expect(await completeLinkCallback('google', 'code', 'st')).toEqual({ success: true })
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toContain('/api/v1/users/me/identities/google/link/callback')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer access')
    expect(JSON.parse(init.body)).toMatchObject({ code: 'code', state: 'st' })
    expect(jar.has('oauth_link_intent')).toBe(false)
  })

  it('returns the API refusal code', async () => {
    jar.set('oauth_state', 'st')
    jar.set(bindingCookieName('oauth'), 'bind')
    jar.set(env.auth.cookieName, 'access')
    fetchMock.mockResolvedValue(json({ code: 'IDENTITY_LINKED_ELSEWHERE', message: 'm' }, 409))
    expect(await completeLinkCallback('google', 'code', 'st')).toEqual({
      success: false,
      code: 'IDENTITY_LINKED_ELSEWHERE',
    })
  })
})
