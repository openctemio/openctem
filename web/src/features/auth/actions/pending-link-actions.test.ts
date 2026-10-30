import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const jar = new Map<string, { value: string; opts?: Record<string, unknown> }>()
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (k: string) => (jar.has(k) ? { value: jar.get(k)!.value } : undefined),
    set: (k: string, v: string, opts?: Record<string, unknown>) => jar.set(k, { value: v, opts }),
    delete: (k: string) => jar.delete(k),
  })),
}))
vi.mock('next/navigation', () => ({ redirect: vi.fn() }))
vi.mock('@/lib/cookies-server', () => ({ setServerCookie: vi.fn() }))
vi.mock('@/lib/api/browser-context-headers', () => ({ browserContextHeaders: async () => ({}) }))

import { env } from '@/lib/env'
import { bindingCookieName } from '@/features/auth/lib/browser-binding'
import { pendingLinkCookieName } from '@/features/auth/lib/oauth-cookies'

import {
  confirmPendingLinkAction,
  dismissPendingLinkAction,
  getPendingLinkAction,
  handleOAuthCallback,
} from './social-auth-actions'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const PENDING = pendingLinkCookieName()

describe('pending link of a refused social sign-in', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    jar.clear()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  const refuse = async (setCookie?: string) => {
    jar.set('oauth_state', { value: 'st' })
    jar.set(bindingCookieName('oauth'), { value: 'bind' })
    const headers = new Headers({ 'Content-Type': 'application/json' })
    if (setCookie) headers.append('Set-Cookie', setCookie)
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          code: 'OAUTH_ACCOUNT_EXISTS',
          message: 'm',
          details: { link_pending: true, provider: 'google' },
        }),
        { status: 409, headers }
      )
    )
    return handleOAuthCallback('google', 'code', 'st')
  }

  it('keeps the pending link in an HttpOnly cookie, and signs nobody in', async () => {
    const r = await refuse(
      '__Host-oauth_pending_link=secret-1; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax'
    )
    expect(r).toMatchObject({ success: false, code: 'OAUTH_ACCOUNT_EXISTS' })
    expect(jar.get(PENDING)).toMatchObject({
      value: 'secret-1',
      opts: { httpOnly: true, sameSite: 'lax', maxAge: 600, path: '/' },
    })
    expect(jar.has(env.auth.cookieName)).toBe(false)
  })

  it('keeps nothing without a usable pending link', async () => {
    await refuse(undefined)
    expect(jar.has(PENDING)).toBe(false)
    await refuse(`oauth_pending_link=${'x'.repeat(129)}; Path=/`)
    expect(jar.has(PENDING)).toBe(false)
    await refuse('oauth_pending_link=bad%20value; Path=/')
    expect(jar.has(PENDING)).toBe(false)
    await refuse('other_cookie=secret-1; Path=/')
    expect(jar.has(PENDING)).toBe(false)
  })

  it('never calls the API without the cookie', async () => {
    jar.set(env.auth.cookieName, { value: 'access' })
    expect(await getPendingLinkAction()).toBeNull()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('describes the pending link with the secret in its cookie and the session token', async () => {
    jar.set(PENDING, { value: 'secret-1' })
    jar.set(env.auth.cookieName, { value: 'access' })
    fetchMock.mockResolvedValue(json({ provider: 'google', email: 'p@gmail.com' }))
    expect(await getPendingLinkAction()).toEqual({ provider: 'google', email: 'p@gmail.com' })
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toContain('/api/v1/me/pending-sign-in-link/describe')
    expect(init.headers.Authorization).toBe('Bearer access')
    expect(init.headers.Cookie).toContain('oauth_pending_link=secret-1')
    expect(init.body).toBeUndefined()
  })

  it('forgets a pending link the API refuses (another account, expired)', async () => {
    jar.set(PENDING, { value: 'secret-1' })
    jar.set(env.auth.cookieName, { value: 'access' })
    fetchMock.mockResolvedValue(json({ code: 'PENDING_LINK_INVALID' }, 404))
    expect(await getPendingLinkAction()).toBeNull()
    expect(jar.has(PENDING)).toBe(false)
  })

  it('ignores a provider it does not know', async () => {
    jar.set(PENDING, { value: 'secret-1' })
    jar.set(env.auth.cookieName, { value: 'access' })
    fetchMock.mockResolvedValue(json({ provider: 'evil', email: 'p@gmail.com' }))
    expect(await getPendingLinkAction()).toBeNull()
  })

  it('confirms once and forgets the cookie', async () => {
    jar.set(PENDING, { value: 'secret-1' })
    jar.set(env.auth.cookieName, { value: 'access' })
    fetchMock.mockResolvedValue(json({ id: 'i', provider: 'google' }))
    expect(await confirmPendingLinkAction()).toEqual({ success: true })
    expect(String(fetchMock.mock.calls[0][0])).toContain('/pending-sign-in-link/confirm')
    expect(jar.has(PENDING)).toBe(false)
  })

  it('keeps the cookie only when a step-up lets the person retry', async () => {
    jar.set(PENDING, { value: 'secret-1' })
    jar.set(env.auth.cookieName, { value: 'access' })
    fetchMock.mockResolvedValue(json({ code: 'STEP_UP_REQUIRED' }, 403))
    expect(await confirmPendingLinkAction()).toEqual({ success: false, code: 'STEP_UP_REQUIRED' })
    expect(jar.has(PENDING)).toBe(true)
    fetchMock.mockResolvedValue(json({ code: 'PENDING_LINK_SIGN_IN_REQUIRED' }, 403))
    expect(await confirmPendingLinkAction()).toEqual({
      success: false,
      code: 'PENDING_LINK_SIGN_IN_REQUIRED',
    })
    expect(jar.has(PENDING)).toBe(false)
  })

  it('"not now" drops it at the API and here', async () => {
    jar.set(PENDING, { value: 'secret-1' })
    jar.set(env.auth.cookieName, { value: 'access' })
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    await dismissPendingLinkAction()
    expect(String(fetchMock.mock.calls[0][0])).toContain('/pending-sign-in-link/cancel')
    expect(jar.has(PENDING)).toBe(false)
  })
})
