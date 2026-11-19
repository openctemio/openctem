/**
 * @vitest-environment node
 */
import { describe, it, expect } from 'vitest'
import { NextRequest } from 'next/server'

import {
  decideAuth,
  handleAuth,
  hasSessionCookie,
  looksLikeJwt,
  requiresAuth,
  returnPath,
  type CookieReader,
} from '../auth'

// Built at runtime so secret scanners do not read a literal token.
const JWT = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJ1MSJ9', 'c2lnbmF0dXJl'].join('.')

function jar(cookies: Record<string, string>): CookieReader {
  return (name) => cookies[name]
}

const COOKIE_STATES: Record<string, Record<string, string>> = {
  none: {},
  access: { auth_token: JWT },
  refresh: { refresh_token: JWT },
  'refresh+tenant': { refresh_token: JWT, app_tenant: '{"id":"t1"}' },
  'malformed refresh': { refresh_token: 'not-a-token', app_tenant: '{"id":"t1"}' },
  'empty access': { auth_token: '' },
  'tenant only': { app_tenant: '{"id":"t1"}' },
}

const SESSION_STATES = new Set(['access', 'refresh', 'refresh+tenant'])
/** A session (refresh token) with no organization selected and no landing marker. */
const NO_ORGANIZATION_STATES = new Set(['refresh'])
/** Protected pages that open before an organization is selected. */
const ORGANIZATION_FREE_PAGES = new Set(['/select-tenant', '/onboarding/create-team'])

const PUBLIC_PAGES = [
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/set-password',
  '/invitations/tok123',
  '/auth/callback/google',
  '/auth/sso/callback/entra',
  '/icon',
  '/opengraph-image',
  '/apple-icon',
]

const API_ROUTES = ['/api/health', '/api/v1/findings', '/api/auth/refresh']

const PROTECTED_PAGES = [
  '/',
  '/findings',
  '/findings/123',
  '/settings/members',
  '/select-tenant',
  '/onboarding/create-team',
  // Segment boundary: a public prefix does not open its look-alikes.
  '/loginx',
  '/invitationsx',
  '/administrators',
  // No console on this site (RFC-022 revision 21): an ordinary page path.
  '/admin',
  '/admin/login',
]

describe('decideAuth: routes x cookie states', () => {
  for (const [state, cookies] of Object.entries(COOKIE_STATES)) {
    describe(`cookies: ${state}`, () => {
      it.each([...PUBLIC_PAGES, ...API_ROUTES])('%s is let through', (pathname) => {
        expect(decideAuth({ pathname, search: '', cookie: jar(cookies) })).toEqual({
          type: 'allow',
        })
      })

      it.each(PROTECTED_PAGES)('%s needs the tenant session', (pathname) => {
        const decision = decideAuth({ pathname, search: '', cookie: jar(cookies) })
        if (NO_ORGANIZATION_STATES.has(state) && !ORGANIZATION_FREE_PAGES.has(pathname)) {
          // Signed in, no organization chosen: the landing picks it first.
          expect(decision.type).toBe('redirect')
          if (decision.type === 'redirect') {
            expect(decision.location.startsWith('/auth/continue')).toBe(true)
            expect(decision.clearCookies).toEqual([])
          }
        } else if (SESSION_STATES.has(state)) {
          expect(decision).toEqual({ type: 'allow' })
        } else {
          expect(decision.type).toBe('redirect')
          if (decision.type === 'redirect') {
            expect(decision.location.startsWith('/login')).toBe(true)
          }
        }
      })
    })
  }
})

describe('the redirect to /login', () => {
  it('carries the deep link (path and query) as next', () => {
    const decision = decideAuth({
      pathname: '/findings/42',
      search: '?tab=evidence&sev=high',
      cookie: jar({}),
    })
    expect(decision).toMatchObject({
      type: 'redirect',
      location: `/login?next=${encodeURIComponent('/findings/42?tab=evidence&sev=high')}`,
    })
  })

  it('leaves next out for the home page', () => {
    expect(decideAuth({ pathname: '/', search: '', cookie: jar({}) })).toMatchObject({
      location: '/login',
    })
  })

  it("drops Next.js's _rsc cache parameter", () => {
    expect(returnPath('/findings', '?_rsc=abc&page=2')).toBe('/findings?page=2')
    expect(returnPath('/findings', '?_rsc=abc')).toBe('/findings')
  })

  it.each(['//evil.example/x', '/\\evil.example', '/a\u202Eb', '/x\u0001y'])(
    'never sends an unsafe next (%j)',
    (pathname) => {
      const decision = decideAuth({ pathname, search: '', cookie: jar({}) })
      expect(decision).toMatchObject({ type: 'redirect', location: '/login' })
    }
  )

  it('expires the stale tenant cookie and a malformed token cookie', () => {
    const decision = decideAuth({
      pathname: '/findings',
      search: '',
      cookie: jar(COOKIE_STATES['malformed refresh']),
    })
    expect(decision).toMatchObject({ type: 'redirect' })
    if (decision.type === 'redirect') {
      expect(decision.clearCookies.sort()).toEqual(['app_tenant', 'refresh_token'])
    }
  })

  it('expires nothing when there is nothing to expire', () => {
    const decision = decideAuth({ pathname: '/findings', search: '', cookie: jar({}) })
    expect(decision).toMatchObject({ type: 'redirect', clearCookies: [] })
  })
})

describe('no redirect loop', () => {
  // The proxy never sends a request with a session-shaped cookie to /login,
  // and never sends anyone away from /login, whatever the cookies: a stale
  // cookie is the client's to clear on its first 401.
  it.each(Object.keys(COOKIE_STATES))('/login is let through with cookies: %s', (state) => {
    expect(
      decideAuth({
        pathname: '/login',
        search: '?next=%2Ffindings',
        cookie: jar(COOKIE_STATES[state]),
      })
    ).toEqual({ type: 'allow' })
  })

  it('a stale (expired, revoked) but well-formed cookie reaches the page', () => {
    expect(
      decideAuth({
        pathname: '/findings',
        search: '',
        cookie: jar({ refresh_token: JWT, app_tenant: '{"id":"t1"}' }),
      })
    ).toEqual({
      type: 'allow',
    })
  })
})

describe('cookie shape', () => {
  it('accepts a JWT and rejects anything else', () => {
    expect(looksLikeJwt(JWT)).toBe(true)
    expect(looksLikeJwt(undefined)).toBe(false)
    expect(looksLikeJwt('')).toBe(false)
    expect(looksLikeJwt('a.b')).toBe(false)
    expect(looksLikeJwt('a.b.c.d')).toBe(false)
    expect(looksLikeJwt('a.b.')).toBe(false)
    expect(looksLikeJwt('a b.c.d')).toBe(false)
    expect(looksLikeJwt(`${'a'.repeat(5000)}.b.c`)).toBe(false)
  })

  it('/login and the proxy agree (hasSessionCookie is shared)', () => {
    expect(hasSessionCookie(jar({ refresh_token: 'garbage' }))).toBe(false)
    expect(hasSessionCookie(jar({ refresh_token: JWT }))).toBe(true)
  })
})

describe('requiresAuth', () => {
  it.each(PUBLIC_PAGES)('%s opens without a session', (path) => {
    expect(requiresAuth(path)).toBe(false)
  })
  it.each(PROTECTED_PAGES)('%s requires a session', (path) => {
    expect(requiresAuth(path)).toBe(true)
  })
})

describe('handleAuth', () => {
  it('redirects to /login?next= on the same origin and expires stale cookies', () => {
    const req = new NextRequest('https://app.example.test/findings/7?tab=x', {
      headers: { cookie: 'app_tenant=%7B%7D' },
    })
    const res = handleAuth(req)
    expect(res).not.toBeNull()
    expect(res!.status).toBe(307)
    expect(res!.headers.get('location')).toBe(
      `https://app.example.test/login?next=${encodeURIComponent('/findings/7?tab=x')}`
    )
    expect(res!.headers.get('set-cookie')).toMatch(/app_tenant=;.*Max-Age=0/i)
  })

  it('lets a request with a session cookie through', () => {
    const req = new NextRequest('https://app.example.test/findings', {
      headers: { cookie: `refresh_token=${JWT}; app_tenant=%7B%22id%22%3A%22t1%22%7D` },
    })
    expect(handleAuth(req)).toBeNull()
  })
})

describe('handleAuth: page loads only', () => {
  it('lets a Server Action POST through (it answers for itself)', () => {
    const req = new NextRequest('https://app.example.test/findings', {
      method: 'POST',
      headers: { 'next-action': 'abc' },
    })
    expect(handleAuth(req)).toBeNull()
  })

  it('redirects a HEAD like a GET', () => {
    const req = new NextRequest('https://app.example.test/findings', { method: 'HEAD' })
    expect(handleAuth(req)?.status).toBe(307)
  })
})

describe('an account-only session (signed in, no organization)', () => {
  const accountOnly = { refresh_token: JWT, auth_token: JWT, app_account_only: '1' }

  it.each([
    '/welcome',
    '/account',
    '/account/security',
    '/account/preferences',
    // An organization that requires 2FA holds the session back: its setup opens.
    '/two-factor-setup',
  ])('%s opens', (pathname) => {
    expect(decideAuth({ pathname, search: '', cookie: jar(accountOnly) })).toEqual({
      type: 'allow',
    })
  })

  it.each([
    '/',
    '/findings',
    '/settings/members',
    '/select-tenant',
    '/onboarding/create-team',
    // Tenant data behind /account stays shut: only the three personal pages open.
    '/account/activity',
    '/account/notifications',
    '/account/connected-apps',
    '/accountx',
  ])('%s redirects to /welcome', (pathname) => {
    expect(decideAuth({ pathname, search: '?x=1', cookie: jar(accountOnly) })).toEqual({
      type: 'redirect',
      location: '/welcome',
      clearCookies: [],
    })
  })

  it('still opens the public pages and the API routes', () => {
    for (const pathname of [
      '/login',
      '/invitations',
      '/not-set-up',
      '/api/v1/users/me',
      '/auth/continue',
    ]) {
      expect(decideAuth({ pathname, search: '', cookie: jar(accountOnly) })).toEqual({
        type: 'allow',
      })
    }
  })

  it('treats a trailing slash like the page itself', () => {
    expect(decideAuth({ pathname: '/welcome/', search: '', cookie: jar(accountOnly) })).toEqual({
      type: 'allow',
    })
  })

  it('lets an organization session through even with a stale marker', () => {
    const member = { ...accountOnly, app_tenant: '{"id":"t1"}' }
    expect(decideAuth({ pathname: '/findings', search: '', cookie: jar(member) })).toEqual({
      type: 'allow',
    })
  })

  it('sends a signed-out visitor of /welcome to the sign-in page, and clears the marker', () => {
    const decision = decideAuth({
      pathname: '/welcome',
      search: '',
      cookie: jar({ app_account_only: '1' }),
    })
    expect(decision).toMatchObject({
      type: 'redirect',
      location: `/login?next=${encodeURIComponent('/welcome')}`,
    })
    if (decision.type === 'redirect') expect(decision.clearCookies).toContain('app_account_only')
  })

  it('redirects a page load through the proxy handler with a 307 to /welcome', () => {
    const req = new NextRequest('https://app.example/findings', {
      headers: { cookie: `refresh_token=${JWT}; app_account_only=1` },
    })
    const res = handleAuth(req)
    expect(res?.status).toBe(307)
    expect(new URL(res!.headers.get('location')!).pathname).toBe('/welcome')
  })
})

describe('a session with no organization selected (the sign-in callback left only tokens)', () => {
  const signedIn = { refresh_token: JWT, auth_token: JWT }

  it('goes to the landing first, keeping the deep link', () => {
    expect(decideAuth({ pathname: '/findings', search: '?x=1', cookie: jar(signedIn) })).toEqual({
      type: 'redirect',
      location: `/auth/continue?next=${encodeURIComponent('/findings?x=1')}`,
      clearCookies: [],
    })
    expect(decideAuth({ pathname: '/', search: '', cookie: jar(signedIn) })).toEqual({
      type: 'redirect',
      location: '/auth/continue',
      clearCookies: [],
    })
  })

  it.each([
    '/welcome',
    '/account',
    '/account/security',
    '/two-factor-setup',
    '/select-tenant',
    '/onboarding/create-team',
    '/ownership-invitations/x',
    '/auth/continue',
    '/login',
    '/invitations',
  ])('%s opens without an organization (no loop through the landing)', (pathname) => {
    expect(decideAuth({ pathname, search: '', cookie: jar(signedIn) })).toEqual({
      type: 'allow',
    })
  })

  // The landing always leaves one of these cookies, so it runs once.
  it.each([
    ['an organization', { app_tenant: '{"id":"t1"}' }],
    ['the account-only marker', { app_account_only: '1' }],
    ['the picker list', { app_pending_tenants: '[]' }],
  ])('runs once: after the landing left %s, no second trip', (_, left) => {
    const decision = decideAuth({
      pathname: '/findings',
      search: '',
      cookie: jar({ ...signedIn, ...left }),
    })
    expect(decision.type === 'redirect' && decision.location.startsWith('/auth/continue')).toBe(
      false
    )
  })

  it('an access token without a refresh token is left to the API (the landing needs one)', () => {
    expect(
      decideAuth({ pathname: '/findings', search: '', cookie: jar({ auth_token: JWT }) })
    ).toEqual({ type: 'allow' })
  })
})
