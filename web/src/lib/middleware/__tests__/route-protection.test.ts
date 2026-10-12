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
const ADMIN_NONCE = 'A'.repeat(43) + '='

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
  'admin console': { admin_csrf: ADMIN_NONCE },
}

const SESSION_STATES = new Set(['access', 'refresh', 'refresh+tenant'])

const PUBLIC_PAGES = [
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/set-password',
  '/invitations/tok123',
  '/auth/callback/google',
  '/auth/sso/callback/entra',
  '/admin/login',
  '/admin/login/callback',
  '/icon',
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
]

const ADMIN_PAGES = ['/admin', '/admin/organizations', '/admin/security/activity']

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
        if (SESSION_STATES.has(state)) {
          expect(decision).toEqual({ type: 'allow' })
        } else {
          expect(decision.type).toBe('redirect')
          if (decision.type === 'redirect') {
            expect(decision.location.startsWith('/login')).toBe(true)
          }
        }
      })

      it.each(ADMIN_PAGES)('%s needs the admin console cookie', (pathname) => {
        const decision = decideAuth({ pathname, search: '', cookie: jar(cookies) })
        if (state === 'admin console') {
          expect(decision).toEqual({ type: 'allow' })
        } else {
          expect(decision.type).toBe('redirect')
          if (decision.type === 'redirect') {
            expect(decision.location).toBe(`/admin/login?next=${encodeURIComponent(pathname)}`)
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
      decideAuth({ pathname: '/findings', search: '', cookie: jar({ refresh_token: JWT }) })
    ).toEqual({
      type: 'allow',
    })
  })

  it('/admin/login is let through without a console cookie', () => {
    expect(
      decideAuth({ pathname: '/admin/login', search: '?next=%2Fadmin', cookie: jar({}) })
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

  it('a malformed admin console cookie does not open the console', () => {
    const decision = decideAuth({
      pathname: '/admin',
      search: '',
      cookie: jar({ admin_csrf: 'x' }),
    })
    expect(decision.type).toBe('redirect')
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
      headers: { cookie: `refresh_token=${JWT}` },
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
