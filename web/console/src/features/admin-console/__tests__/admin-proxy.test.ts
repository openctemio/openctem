/**
 * @vitest-environment node
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/env', () => ({
  env: {
    api: { url: 'http://api.test' },
    auth: { refreshCookieName: 'refresh_token', cookieName: 'auth_token' },
  },
}))

import { POST, GET } from '@console/app/api/v1/admin/[...path]/route'

const COOKIES =
  'auth_token=tenant-access; refresh_token=signed-in-refresh; csrf_token=tenant-csrf; admin_session=console; admin_csrf=c1; admin_idp=idp-state'

function call(
  handler: typeof POST,
  method: string,
  path: string[],
  extra: Record<string, string> = {}
) {
  const req = new NextRequest(`http://ui.test/api/v1/admin/${path.join('/')}`, {
    method,
    // A same-origin browser write: Origin and the admin double-submit pair.
    headers: {
      cookie: COOKIES,
      authorization: 'Bearer tenant-access',
      origin: 'http://ui.test',
      'x-csrf-token': 'c1',
      ...extra,
    },
  })
  return handler(req, { params: Promise.resolve({ path }) })
}

describe('admin API proxy', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  const sentCookie = () => (fetchMock.mock.calls[0][1].headers as Headers).get('Cookie') ?? ''
  const sentAuth = () => (fetchMock.mock.calls[0][1].headers as Headers).get('Authorization')

  it.each([
    ['auth', 'login'],
    ['auth', 'logout'],
    ['auth', 'mfa'],
  ])('never forwards the tenant refresh token, not even to %s/%s', async (...path) => {
    await call(POST, 'POST', path)
    expect(sentCookie()).not.toContain('refresh_token')
    expect(sentCookie()).toContain('admin_session=console')
  })

  it('forwards the step-up code of a protected action', async () => {
    await call(POST, 'POST', ['administrators'], { 'x-admin-step-up': '123456' })
    expect((fetchMock.mock.calls[0][1].headers as Headers).get('x-admin-step-up')).toBe('123456')
  })

  it('never forwards tenant credentials', async () => {
    await call(POST, 'POST', ['auth', 'login'])
    expect(sentCookie()).not.toContain('auth_token')
    expect(sentCookie()).not.toContain('csrf_token')
    expect(sentAuth()).toBeNull()
  })

  it('forwards the identity-provider sign-in cookie to the callback', async () => {
    await call(POST, 'POST', ['auth', 'idp', 'callback'])
    expect(sentCookie()).toContain('admin_idp=idp-state')
    expect(sentCookie()).not.toContain('refresh_token')
  })

  function send(method: string, path: string[], body: BodyInit, contentLength: number) {
    const req = new NextRequest('http://ui.test/api/v1/admin/' + path.join('/'), {
      method,
      body,
      headers: {
        cookie: COOKIES,
        origin: 'http://ui.test',
        'x-csrf-token': 'c1',
        'content-length': String(contentLength),
      },
    })
    return POST(req, { params: Promise.resolve({ path }) })
  }

  it('forwards an upload body byte for byte (binary archives survive)', async () => {
    const bytes = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x80, 0x00])
    await send('POST', ['content-packs'], bytes, bytes.length)
    const sent = new Uint8Array(fetchMock.mock.calls[0][1].body as ArrayBuffer)
    expect(Array.from(sent)).toEqual(Array.from(bytes))
  })

  it('allows a large body only for a content pack upload', async () => {
    const big = 5 * 1024 * 1024
    const tooBigElsewhere = await send('POST', ['tenants'], 'x', big)
    expect(tooBigElsewhere.status).toBe(413)
    expect(fetchMock).not.toHaveBeenCalled()
    const tooBigUpload = await send('POST', ['content-packs'], 'x', 200 * 1024 * 1024)
    expect(tooBigUpload.status).toBe(413)
  })

  it('passes a download through as bytes with its file name', async () => {
    const archive = new Uint8Array([0x1f, 0x8b, 0x00, 0xff])
    fetchMock.mockResolvedValueOnce(
      new Response(archive, {
        status: 200,
        headers: {
          'content-type': 'application/gzip',
          'content-disposition': 'attachment; filename="pack.tar.gz"',
        },
      })
    )
    const res = await call(GET, 'GET', ['content-packs', 'abc', 'download'])
    expect(res.headers.get('content-disposition')).toBe('attachment; filename="pack.tar.gz"')
    expect(res.headers.get('content-type')).toBe('application/gzip')
    expect(Array.from(new Uint8Array(await res.arrayBuffer()))).toEqual(Array.from(archive))
  })

  it("keeps the API's CSP on the console API reference page", async () => {
    const csp = "default-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    fetchMock.mockResolvedValueOnce(
      new Response('<!DOCTYPE html>', {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': csp },
      })
    )
    const res = await call(GET, 'GET', ['docs'])
    expect(res.headers.get('content-security-policy')).toBe(csp)
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8')
  })

  describe('client IP headers', () => {
    afterEach(() => vi.unstubAllEnvs())

    function callWithIp() {
      const req = new NextRequest('http://ui.test/api/v1/admin/tenants', {
        method: 'GET',
        headers: { 'x-real-ip': '203.0.113.7', 'x-forwarded-for': '203.0.113.7' },
      })
      return GET(req, { params: Promise.resolve({ path: ['tenants'] }) })
    }
    const sent = () => fetchMock.mock.calls[0][1].headers as Headers

    it('drops browser-supplied forwarding headers by default', async () => {
      vi.stubEnv('TRUST_PROXY_HEADERS', '')
      await callWithIp()
      expect(sent().get('x-real-ip')).toBeNull()
      expect(sent().get('x-forwarded-for')).toBeNull()
    })

    it('forwards them when TRUST_PROXY_HEADERS=true', async () => {
      vi.stubEnv('TRUST_PROXY_HEADERS', 'true')
      await callWithIp()
      expect(sent().get('x-real-ip')).toBe('203.0.113.7')
      expect(sent().get('x-forwarded-for')).toBe('203.0.113.7')
    })
  })

  it('forwards the background-read marker so the API can leave the idle clock alone', async () => {
    await call(GET, 'GET', ['overview'], { 'x-admin-background': '1' })
    expect((fetchMock.mock.calls[0][1].headers as Headers).get('x-admin-background')).toBe('1')
  })

  it('does not tell the browser why the API could not be reached', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock.mockRejectedValueOnce(new Error('connect ECONNREFUSED 10.1.2.3:8081'))
    const res = await call(GET, 'GET', ['overview'])
    expect(res.status).toBe(502)
    const body = await res.text()
    expect(body).not.toContain('10.1.2.3')
    expect(body).not.toContain('ECONNREFUSED')
    spy.mockRestore()
  })
})
