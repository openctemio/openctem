/**
 * Browser side of the CSRF double submit: every same-origin state-changing
 * fetch carries X-CSRF-Token, including the requests Next.js makes for the
 * Server Actions behind the sign-in, registration, password-reset, invitation
 * and second-factor forms (src/lib/csrf-client.ts).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { csrfHeaders, installCsrfFetch, readCsrfCookie, withCsrfHeader } from '@/lib/csrf-client'

const ORIGIN = window.location.origin

function setCookie(value: string | null) {
  document.cookie =
    value === null ? 'csrf_token=; max-age=0; path=/' : `csrf_token=${value}; path=/`
}

describe('csrf-client', () => {
  beforeEach(() => setCookie('tok-1'))
  afterEach(() => {
    setCookie(null)
    vi.unstubAllGlobals()
  })

  it('reads the cookie', () => {
    expect(readCsrfCookie()).toBe('tok-1')
    expect(csrfHeaders()).toEqual({ 'X-CSRF-Token': 'tok-1' })
    setCookie(null)
    expect(readCsrfCookie()).toBe('')
    expect(csrfHeaders()).toEqual({})
  })

  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'post'])(
    'adds the header to a same-origin %s',
    (m) => {
      const init = withCsrfHeader('/api/v1/x', { method: m }, ORIGIN)
      expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe('tok-1')
    }
  )

  it.each(['GET', 'HEAD', 'OPTIONS'])('leaves %s alone', (m) => {
    const init = { method: m }
    expect(withCsrfHeader('/api/v1/x', init, ORIGIN)).toBe(init)
  })

  it('never sends the token to another origin', () => {
    const init = { method: 'POST' }
    expect(withCsrfHeader('https://evil.example/x', init, ORIGIN)).toBe(init)
    expect(withCsrfHeader('//evil.example/x', init, ORIGIN)).toBe(init)
  })

  it('keeps a header the caller set (admin console sends admin_csrf)', () => {
    const init = { method: 'POST', headers: { 'X-CSRF-Token': 'admin' } }
    expect(withCsrfHeader('/api/v1/admin/x', init, ORIGIN)).toBe(init)
  })

  it('keeps the other headers and reads a Request', () => {
    const r = new Request(`${ORIGIN}/api/v1/x`, { method: 'POST', headers: { 'X-A': '1' } })
    const h = new Headers(withCsrfHeader(r, undefined, ORIGIN)?.headers)
    expect(h.get('X-A')).toBe('1')
    expect(h.get('X-CSRF-Token')).toBe('tok-1')
  })

  it('sends nothing when there is no cookie', () => {
    setCookie(null)
    const init = { method: 'POST' }
    expect(withCsrfHeader('/x', init, ORIGIN)).toBe(init)
  })

  describe('installCsrfFetch', () => {
    it('gives a Server Action request (the sign-in form) the header', async () => {
      const original = vi.fn(async () => new Response(null, { status: 200 }))
      vi.stubGlobal('fetch', original)
      installCsrfFetch(window)
      // The shape Next.js uses for a Server Action call.
      await window.fetch('/login', {
        method: 'POST',
        headers: { Accept: 'text/x-component', 'next-action': '7f00aa' },
        body: '[{"email":"a@example.com"}]',
      })
      const sent = new Headers(((original.mock.calls[0] as unknown[])[1] as RequestInit).headers)
      expect(sent.get('X-CSRF-Token')).toBe('tok-1')
      expect(sent.get('next-action')).toBe('7f00aa')
    })

    it('installs once', () => {
      vi.stubGlobal('fetch', vi.fn())
      installCsrfFetch(window)
      const first = window.fetch
      installCsrfFetch(window)
      expect(window.fetch).toBe(first)
    })

    it('is installed by instrumentation-client before the app runs', async () => {
      const original = vi.fn(async () => new Response(null, { status: 200 }))
      vi.stubGlobal('fetch', original)
      vi.resetModules()
      await import('@/instrumentation-client')
      await window.fetch('/register', { method: 'POST' })
      const sent = new Headers(((original.mock.calls[0] as unknown[])[1] as RequestInit).headers)
      expect(sent.get('X-CSRF-Token')).toBe('tok-1')
    })
  })
})
