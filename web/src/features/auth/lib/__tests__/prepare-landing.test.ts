/**
 * prepareLanding (sign-in-landing.ts): the one organization's refusal is
 * carried to the account space, so it can name the reason and its next step.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const store = new Map<string, string>()
vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (store.has(name) ? { value: store.get(name) } : undefined),
    set: (name: string, value: string) => store.set(name, value),
    delete: (name: string) => store.delete(name),
  }),
}))
vi.mock('@/lib/api/browser-context-headers', () => ({ browserContextHeaders: async () => ({}) }))

import { env } from '@/lib/env'
import { prepareLanding } from '../sign-in-landing'

const ORG = '0b1e2c3d-0000-4000-8000-000000000001'

/** The API: an account token, one membership, and the organization's answer. */
function api(exchange: { status: number; body: Record<string, unknown> }, admission?: string) {
  return vi.fn(async (url: string) => {
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      })
    if (url.endsWith('/auth/account-token'))
      return json(200, { access_token: 'acct', refresh_token: 'r2', expires_in: 900 })
    if (url.includes('/users/me/tenants'))
      return json(200, [{ id: ORG, slug: 'acme', name: 'Acme', role: 'member', admission }])
    if (url.endsWith('/auth/token')) return json(exchange.status, exchange.body)
    return json(404, {})
  })
}

describe('prepareLanding', () => {
  beforeEach(() => {
    store.clear()
    store.set(env.auth.refreshCookieName, 'r1')
  })

  it.each(['SSO_REQUIRED', 'OWN_SIGN_IN_REQUIRED', 'MFA_IDP_EVIDENCE_REQUIRED'])(
    'refused with %s: the account space, with the code and the organization',
    async (code) => {
      vi.stubGlobal('fetch', api({ status: 403, body: { code } }))
      await expect(prepareLanding()).resolves.toEqual({
        kind: 'account',
        refusal: { code, slug: 'acme' },
      })
      // The session stays (account-only), no organization is selected.
      expect(store.get(env.cookies.accountOnly)).toBe('1')
      expect(store.has(env.cookies.tenant)).toBe(false)
    }
  )

  it('the listing already names the refusal: no token request, the account space says why', async () => {
    const fetchMock = api({ status: 200, body: { access_token: 'org' } }, 'SSO_REQUIRED')
    vi.stubGlobal('fetch', fetchMock)
    await expect(prepareLanding()).resolves.toEqual({
      kind: 'account',
      refusal: { code: 'SSO_REQUIRED', slug: 'acme' },
    })
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/auth/token'))).toBe(false)
    expect(store.has(env.cookies.tenant)).toBe(false)
  })

  it.each(['open', 'MFA_ENROLLMENT_REQUIRED'])(
    'admission %s: the token request still decides',
    async (admission) => {
      const fetchMock = api({ status: 403, body: { code: 'SSO_REQUIRED' } }, admission)
      vi.stubGlobal('fetch', fetchMock)
      await expect(prepareLanding()).resolves.toEqual({
        kind: 'account',
        refusal: { code: 'SSO_REQUIRED', slug: 'acme' },
      })
      expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/auth/token'))).toBe(true)
    }
  )

  it.each([429, 503])(
    'a %i from the token request: unavailable, not the plain account space',
    async (status) => {
      vi.stubGlobal('fetch', api({ status, body: { code: 'RATE_LIMIT_EXCEEDED' } }))
      await expect(prepareLanding()).resolves.toEqual({ kind: 'unavailable' })
    }
  )

  it('two-factor required: the setup step, not the account space', async () => {
    vi.stubGlobal('fetch', api({ status: 403, body: { code: 'MFA_ENROLLMENT_REQUIRED' } }))
    await expect(prepareLanding()).resolves.toEqual({ kind: 'two_factor', tenantId: ORG })
  })

  it('admitted: the organization is selected', async () => {
    vi.stubGlobal(
      'fetch',
      api({
        status: 200,
        body: { access_token: 'org', tenant_id: ORG, tenant_slug: 'acme', role: 'member' },
      })
    )
    await expect(prepareLanding()).resolves.toEqual({ kind: 'organization', tenantId: ORG })
    expect(store.get(env.cookies.tenant)).toContain('"slug":"acme"')
  })
})
