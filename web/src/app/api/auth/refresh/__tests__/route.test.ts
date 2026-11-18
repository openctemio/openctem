/**
 * /api/auth/refresh with no organization selected: it renews the account-only
 * token (any signed-in person can have one) and marks the session, instead of
 * failing, which the client read as a dead session and signed the person out
 * on their first social sign-in. Only a refused refresh token ends it.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mocks = vi.hoisted(() => ({
  cookies: new Map<string, string>(),
  account: vi.fn(),
  refreshOnce: vi.fn(),
}))

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) =>
      mocks.cookies.has(name) ? { name, value: mocks.cookies.get(name) } : undefined,
  }),
}))
vi.mock('@/lib/server-auth-cookies', () => ({ csrfRejection: () => null }))
vi.mock('@/features/auth/lib/account-session', () => ({ requestAccountToken: mocks.account }))
vi.mock('@/lib/server-refresh', () => ({ refreshSessionOnce: mocks.refreshOnce }))

import { env } from '@/lib/env'
import { POST } from '../route'

function request() {
  return new NextRequest('http://localhost/api/auth/refresh', { method: 'POST' })
}

beforeEach(() => {
  mocks.cookies.clear()
  mocks.account.mockReset()
  mocks.refreshOnce.mockReset()
})

describe('POST /api/auth/refresh without an organization', () => {
  it('renews the account-only token and sets the marker (first social sign-in)', async () => {
    mocks.cookies.set(env.auth.refreshCookieName, 'rt')
    mocks.account.mockResolvedValue({
      ok: true,
      accessToken: 'account-at',
      refreshToken: 'rt-2',
      expiresIn: 900,
    })
    const res = await POST(request())
    expect(res.status).toBe(200)
    expect(mocks.account).toHaveBeenCalledWith('rt')
    expect(mocks.refreshOnce).not.toHaveBeenCalled()
    expect(res.cookies.get(env.auth.cookieName)?.value).toBe('account-at')
    expect(res.cookies.get(env.auth.refreshCookieName)?.value).toBe('rt-2')
    expect(res.cookies.get(env.cookies.accountOnly)?.value).toBe('1')
  })

  it('answers 401 and clears the cookies only when the session is gone', async () => {
    mocks.cookies.set(env.auth.refreshCookieName, 'rt')
    mocks.account.mockResolvedValue({ ok: false, code: 'SESSION' })
    const res = await POST(request())
    expect(res.status).toBe(401)
    expect(res.cookies.get(env.auth.refreshCookieName)?.value).toBe('')
  })

  it('answers 502 and keeps the cookies when the API did not answer', async () => {
    mocks.cookies.set(env.auth.refreshCookieName, 'rt')
    mocks.account.mockResolvedValue({ ok: false, code: 'ERROR' })
    const res = await POST(request())
    expect(res.status).toBe(502)
    expect(res.cookies.get(env.auth.refreshCookieName)).toBeUndefined()
  })

  it('with an organization selected, refreshes that organization token', async () => {
    mocks.cookies.set(env.auth.refreshCookieName, 'rt')
    mocks.cookies.set(
      env.cookies.tenant,
      JSON.stringify({ id: 't1', slug: 'acme', role: 'member' })
    )
    mocks.refreshOnce.mockResolvedValue({ ok: false, status: 403, code: 'MFA_ENROLLMENT_REQUIRED' })
    const res = await POST(request())
    expect(mocks.account).not.toHaveBeenCalled()
    expect(res.status).toBe(403)
    // A 2FA refusal keeps the session for the setup page.
    expect(res.cookies.get(env.auth.refreshCookieName)).toBeUndefined()
  })

  it('a removed member loses only the organization cookie, not the session', async () => {
    mocks.cookies.set(env.auth.refreshCookieName, 'rt')
    mocks.cookies.set(
      env.cookies.tenant,
      JSON.stringify({ id: 't1', slug: 'acme', role: 'member' })
    )
    mocks.refreshOnce.mockResolvedValue({
      ok: false,
      status: 403,
      code: 'ORGANIZATION_ACCESS_DENIED',
    })
    const res = await POST(request())
    expect(res.status).toBe(403)
    expect(res.cookies.get(env.cookies.tenant)?.value).toBe('')
    expect(res.cookies.get(env.auth.refreshCookieName)).toBeUndefined()
    // That organization's access token goes with it, like every other
    // account-space refusal (refresh-failure.ts).
    expect(res.cookies.get(env.auth.cookieName)?.value).toBe('')
  })
})

describe('POST /api/auth/refresh refused by the organization', () => {
  function inOrganization() {
    mocks.cookies.set(env.auth.refreshCookieName, 'rt')
    mocks.cookies.set(env.auth.cookieName, 'at')
    mocks.cookies.set(
      env.cookies.tenant,
      JSON.stringify({ id: 't1', slug: 'acme', role: 'member' })
    )
  }

  it.each([
    'ORGANIZATION_SUSPENDED',
    'SSO_REQUIRED',
    'MFA_IDP_EVIDENCE_REQUIRED',
    'EMAIL_NOT_VERIFIED',
    'PERSONAL_ACCOUNTS_BLOCKED',
  ])(
    '%s keeps the session for the account space, drops the organization and its token',
    async (code) => {
      inOrganization()
      mocks.refreshOnce.mockResolvedValue({ ok: false, status: 403, code })
      const res = await POST(request())
      expect(res.status).toBe(403)
      expect(res.cookies.get(env.auth.refreshCookieName)).toBeUndefined()
      expect(res.cookies.get(env.auth.cookieName)?.value).toBe('')
      expect(res.cookies.get(env.cookies.tenant)?.value).toBe('')
    }
  )

  it('OWN_SIGN_IN_REQUIRED ends the session', async () => {
    inOrganization()
    mocks.refreshOnce.mockResolvedValue({ ok: false, status: 403, code: 'OWN_SIGN_IN_REQUIRED' })
    const res = await POST(request())
    expect(res.cookies.get(env.auth.refreshCookieName)?.value).toBe('')
    expect(res.cookies.get(env.cookies.tenant)?.value).toBe('')
  })
})
