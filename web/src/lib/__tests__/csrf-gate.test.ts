/**
 * @vitest-environment node
 *
 * CSRF on every state-changing request the web server answers
 * (src/lib/server-auth-cookies.ts): the pre-session Server Actions behind
 * src/proxy.ts (sign-in, registration, password reset, invitation, second
 * factor, SSO start) and every route handler. A missing cookie is a refusal,
 * never a pass.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'

import { proxy } from '@/proxy'
import { POST as refreshPOST } from '@/app/api/auth/refresh/route'
import { POST as switchTeamPOST } from '@/app/api/auth/switch-team/route'
import { POST as v1POST, DELETE as v1DELETE } from '@/app/api/v1/[...path]/route'
import { POST as adminPOST } from '@/app/api/v1/admin/[...path]/route'
import { CSRF_COOKIE, csrfRejection } from '@/lib/server-auth-cookies'

const APP = 'https://app.example.test'
const TOKEN = 'a'.repeat(64)

interface Shape {
  cookie?: string | null
  header?: string | null
  origin?: string | null
  referer?: string | null
  site?: string | null
  method?: string
  extraHeaders?: Record<string, string>
}

/** A browser request from the app's own page, with any part changed. */
function req(path: string, shape: Shape = {}): NextRequest {
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  const cookie = shape.cookie === undefined ? TOKEN : shape.cookie
  const header = shape.header === undefined ? TOKEN : shape.header
  const origin = shape.origin === undefined ? APP : shape.origin
  const site = shape.site === undefined ? 'same-origin' : shape.site
  if (cookie !== null) headers.cookie = `${CSRF_COOKIE}=${cookie}`
  if (header !== null) headers['x-csrf-token'] = header
  if (origin !== null) headers.origin = origin
  if (shape.referer) headers.referer = shape.referer
  if (site !== null) headers['sec-fetch-site'] = site
  Object.assign(headers, shape.extraHeaders)
  return new NextRequest(`${APP}${path}`, {
    method: shape.method ?? 'POST',
    headers,
    body: '{}',
  })
}

/** The forged and malformed shapes every state-changing entry point must refuse. */
const REFUSED: Array<[string, Shape]> = [
  ['no csrf_token cookie', { cookie: null }],
  ['no X-CSRF-Token header', { header: null }],
  ['a header that does not match the cookie', { header: 'b'.repeat(64) }],
  ['a header of another length', { header: 'a' }],
  ['a foreign Origin', { origin: 'https://evil.example', site: 'cross-site' }],
  ['a foreign Origin without Sec-Fetch-Site', { origin: 'https://evil.example', site: null }],
  ['a sibling subdomain', { origin: 'https://x.app.example.test', site: 'same-site' }],
  ['Sec-Fetch-Site cross-site', { site: 'cross-site' }],
  ['an opaque Origin', { origin: 'null' }],
  ['neither Origin nor Referer', { origin: null, site: null }],
  ['a foreign Referer and no Origin', { origin: null, referer: 'https://evil.example/x' }],
]

describe('csrfRejection', () => {
  it.each(REFUSED)('refuses %s', async (_, shape) => {
    const res = csrfRejection(req('/x', shape))
    expect(res?.status).toBe(403)
    expect(await res?.json()).toMatchObject({ error: { code: 'CSRF_INVALID' } })
  })

  it('lets a same-origin request with the pair through', () => {
    expect(csrfRejection(req('/x'))).toBeNull()
  })

  it('falls back to Referer when there is no Origin', () => {
    expect(csrfRejection(req('/x', { origin: null, referer: `${APP}/login` }))).toBeNull()
  })

  it('accepts Sec-Fetch-Site none (user-initiated)', () => {
    expect(csrfRejection(req('/x', { site: 'none' }))).toBeNull()
  })

  it('compares with the host the gateway forwarded', () => {
    const r = new NextRequest('http://web:3000/x', {
      method: 'POST',
      headers: {
        cookie: `${CSRF_COOKIE}=${TOKEN}`,
        'x-csrf-token': TOKEN,
        origin: APP,
        host: 'web:3000',
        'x-forwarded-host': 'app.example.test',
      },
    })
    expect(csrfRejection(r)).toBeNull()
  })

  it.each(['PUT', 'PATCH', 'DELETE'])('checks %s', (method) => {
    expect(csrfRejection(req('/x', { method, cookie: null }))?.status).toBe(403)
  })

  it.each(['GET', 'HEAD', 'OPTIONS'])('does not check %s', (method) => {
    const r = new NextRequest(`${APP}/x`, { method })
    expect(csrfRejection(r)).toBeNull()
  })

  it('accepts an extra double-submit cookie when the route names it', () => {
    const r = req('/x', { cookie: null, header: 'c1', extraHeaders: { cookie: 'admin_csrf=c1' } })
    expect(csrfRejection(r)).toHaveProperty('status', 403)
    expect(csrfRejection(r, ['admin_csrf'])).toBeNull()
  })
})

describe('proxy.ts: Server Actions (pre-session forms)', () => {
  // A Server Action is a POST to the page that renders the form.
  const PAGES = [
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    '/set-password',
    '/invitations',
    '/select-tenant',
    '/onboarding/create-team',
  ]
  const action = { 'next-action': '7f00aa' }

  describe.each(PAGES)('%s', (page) => {
    it.each(REFUSED)('refuses %s', (_, shape) => {
      const res = proxy(req(page, { ...shape, extraHeaders: action }))
      expect(res.status).toBe(403)
    })

    it('lets the real form through', () => {
      const res = proxy(req(page, { extraHeaders: action }))
      expect(res.status).not.toBe(403)
    })
  })

  it('sets a csrf_token cookie on a page that has none (before sign-in)', () => {
    const res = proxy(new NextRequest(`${APP}/login`))
    const set = res.cookies.get(CSRF_COOKIE)
    expect(set?.value).toMatch(/^[0-9a-f]{64}$/)
    expect(set?.httpOnly).toBe(false)
    expect(set?.sameSite).toBe('lax')
    expect(set?.path).toBe('/')
  })

  it('keeps an existing csrf_token cookie', () => {
    const res = proxy(
      new NextRequest(`${APP}/login`, { headers: { cookie: `csrf_token=${TOKEN}` } })
    )
    expect(res.cookies.get(CSRF_COOKIE)).toBeUndefined()
  })

  it('sets the cookie on the sign-in redirect too', () => {
    const res = proxy(new NextRequest(`${APP}/findings`))
    expect(res.status).toBe(307)
    expect(res.cookies.get(CSRF_COOKIE)?.value).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('route handlers', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    vi.mocked(cookies).mockImplementation(
      async () =>
        ({
          // The API proxy reads the cookies it forwards from here.
          get: (name: string) => (name === CSRF_COOKIE ? { name, value: TOKEN } : undefined),
          set: vi.fn(),
          delete: vi.fn(),
        }) as unknown as Awaited<ReturnType<typeof cookies>>
    )
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  type Handler = (r: NextRequest) => Promise<NextResponse>
  const v1 =
    (path: string[], h = v1POST) =>
    (r: NextRequest) =>
      h(r, { params: Promise.resolve({ path }) })

  const ROUTES: Array<[string, string, Handler]> = [
    ['POST /api/auth/refresh', '/api/auth/refresh', refreshPOST],
    ['POST /api/auth/switch-team', '/api/auth/switch-team', switchTeamPOST],
    ['POST /api/v1/auth/login', '/api/v1/auth/login', v1(['auth', 'login'])],
    ['POST /api/v1/auth/register', '/api/v1/auth/register', v1(['auth', 'register'])],
    [
      'POST /api/v1/auth/forgot-password',
      '/api/v1/auth/forgot-password',
      v1(['auth', 'forgot-password']),
    ],
    [
      'POST /api/v1/auth/reset-password',
      '/api/v1/auth/reset-password',
      v1(['auth', 'reset-password']),
    ],
    ['POST /api/v1/auth/mfa/verify', '/api/v1/auth/mfa/verify', v1(['auth', 'mfa', 'verify'])],
    [
      'POST /api/v1/invitations/accept',
      '/api/v1/invitations/accept',
      v1(['invitations', 'accept']),
    ],
    ['DELETE /api/v1/assets/1', '/api/v1/assets/1', v1(['assets', '1'], v1DELETE)],
    [
      'POST /api/v1/admin/auth/login',
      '/api/v1/admin/auth/login',
      (r) => adminPOST(r, { params: Promise.resolve({ path: ['auth', 'login'] }) }),
    ],
  ]

  describe.each(ROUTES)('%s', (_, path, handler) => {
    it.each(REFUSED)('refuses %s without calling the API', async (__, shape) => {
      const method = path.endsWith('/assets/1') ? 'DELETE' : 'POST'
      const res = await handler(req(path, { ...shape, method }))
      expect(res.status).toBe(403)
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('lets the real request through', async () => {
      const method = path.endsWith('/assets/1') ? 'DELETE' : 'POST'
      const res = await handler(req(path, { method }))
      expect(res.status).not.toBe(403)
    })
  })

  it('the API proxy forwards the pair it checked', async () => {
    await v1(['auth', 'login'])(req('/api/v1/auth/login'))
    const sent = fetchMock.mock.calls[0][1].headers as Headers
    expect(sent.get('x-csrf-token')).toBe(TOKEN)
    expect(sent.get('cookie')).toContain(`csrf_token=${TOKEN}`)
  })
})
