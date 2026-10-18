/**
 * @vitest-environment node
 *
 * With the console on a port of its own (RFC-022 revision 21), the tenant
 * site on the same host is another origin but the same site, and shares the
 * host's cookies. A write from a tenant page must never reach the console
 * API, even with a matching double-submit pair in the shared cookie jar.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/env', () => ({
  env: {
    api: { url: 'http://api.test', adminUrl: 'http://api-admin.test' },
    auth: { refreshCookieName: 'refresh_token', cookieName: 'auth_token' },
  },
}))

import { POST } from '@console/app/api/v1/admin/[...path]/route'

const CONSOLE = 'https://ctem.example.test:8443'

function write(
  origin: string,
  site: string,
  cookie = 'console_csrf=t1; admin_session=s; admin_csrf=c1',
  token = 'c1'
) {
  const req = new NextRequest(`${CONSOLE}/api/v1/admin/tenants`, {
    method: 'POST',
    headers: {
      host: 'ctem.example.test:8443',
      origin,
      'sec-fetch-site': site,
      cookie,
      'x-csrf-token': token,
      'content-type': 'application/json',
    },
    body: '{}',
  })
  return POST(req, { params: Promise.resolve({ path: ['tenants'] }) })
}

describe('console API proxy and the tenant origin', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it.each([
    ['the tenant site on 443, same site', 'https://ctem.example.test', 'same-site'],
    ['the tenant site, no fetch metadata', 'https://ctem.example.test', ''],
    ['another port of the host', 'https://ctem.example.test:4443', 'same-site'],
    ['a sibling host name', 'https://app.example.test', 'same-site'],
  ])('refuses a write from %s', async (_, origin, site) => {
    const res = await write(origin, site)
    expect(res.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('forwards a write from its own origin to the console listener', async () => {
    const res = await write(CONSOLE, 'same-origin')
    expect(res.status).toBe(204)
    expect(String(fetchMock.mock.calls[0][0])).toBe('http://api-admin.test/api/v1/admin/tenants')
  })

  it('does not accept the tenant site csrf_token as the console pre-session pair', async () => {
    // Sign-in step: no console session yet, only the tenant site's cookie.
    const res = await write(CONSOLE, 'same-origin', 'csrf_token=tenant', 'tenant')
    expect(res.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('accepts the console_csrf pre-session pair', async () => {
    const res = await write(CONSOLE, 'same-origin', 'console_csrf=pre', 'pre')
    expect(res.status).toBe(204)
  })

  it('sends HSTS with every console response (host mode has no other source)', async () => {
    const { default: config } = await import('../../next.config')
    const rules = (await config.headers?.()) ?? []
    const all = rules.find((r) => r.source === '/:path*')
    const hsts = all?.headers.find((h) => h.key === 'Strict-Transport-Security')
    expect(hsts?.value).toMatch(/max-age=\d{7,}/)
  })
})
