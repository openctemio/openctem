import { describe, it, expect, afterEach, vi } from 'vitest'

const incoming = vi.hoisted(() => ({ headers: new Headers() }))

vi.mock('next/headers', () => ({
  headers: async () => incoming.headers,
}))

import { browserContextHeaders } from '@/lib/api/browser-context-headers'

// What the API would count a request against, given the headers the web sends
// it from a trusted peer: the right-most X-Forwarded-For entry, else the peer
// (server/pkg/httpsec/clientip.go). With no forwarded header, every request
// counts against this server's own address.
const WEB_PEER = '172.30.80.11'
function apiKeyFor(sent: Record<string, string>): string {
  const xff = sent['x-forwarded-for']
  if (!xff) return WEB_PEER
  const entries = xff.split(',')
  return entries[entries.length - 1].trim()
}

describe('browserContextHeaders', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    incoming.headers = new Headers()
  })

  it('passes the User-Agent on', async () => {
    incoming.headers = new Headers({ 'user-agent': 'Browser/1.0' })
    expect(await browserContextHeaders()).toEqual({ 'User-Agent': 'Browser/1.0' })
  })

  describe('with TRUST_PROXY_HEADERS off', () => {
    it.each(['', 'false', '1'])('sends no client address (TRUST_PROXY_HEADERS=%j)', async (v) => {
      vi.stubEnv('TRUST_PROXY_HEADERS', v)
      incoming.headers = new Headers({
        'x-forwarded-for': '203.0.113.7',
        'x-real-ip': '203.0.113.8',
      })
      const sent = await browserContextHeaders()
      expect(sent['x-forwarded-for']).toBeUndefined()
      expect(sent['x-real-ip']).toBeUndefined()
      expect(Object.keys(sent).map((k) => k.toLowerCase())).not.toContain('x-forwarded-for')
    })

    it('a request header does not change the address the API counts', async () => {
      vi.stubEnv('TRUST_PROXY_HEADERS', '')
      const keys = new Set<string>()
      for (const value of [undefined, '203.0.113.1', '203.0.113.2', '2001:db8::9']) {
        incoming.headers = new Headers(value ? { 'x-forwarded-for': value } : {})
        keys.add(apiKeyFor(await browserContextHeaders()))
      }
      expect([...keys]).toEqual([WEB_PEER])
    })
  })

  describe('with TRUST_PROXY_HEADERS on', () => {
    it('sends the address the trusted proxy reported', async () => {
      vi.stubEnv('TRUST_PROXY_HEADERS', 'true')
      incoming.headers = new Headers({ 'x-forwarded-for': '198.51.100.20' })
      const sent = await browserContextHeaders()
      expect(sent['x-forwarded-for']).toBe('198.51.100.20')
      expect(sent['x-real-ip']).toBe('198.51.100.20')
    })

    it('entries left of the trusted hop do not change the address the API counts', async () => {
      vi.stubEnv('TRUST_PROXY_HEADERS', 'true')
      const keys = new Set<string>()
      for (const prefix of ['', '203.0.113.1, ', '203.0.113.2, 192.0.2.5, ', 'junk, ']) {
        incoming.headers = new Headers({ 'x-forwarded-for': `${prefix}198.51.100.20` })
        const sent = await browserContextHeaders()
        expect(sent['x-forwarded-for']).toBe('198.51.100.20')
        keys.add(apiKeyFor(sent))
      }
      expect([...keys]).toEqual(['198.51.100.20'])
    })

    it('sends nothing for a malformed trusted entry', async () => {
      vi.stubEnv('TRUST_PROXY_HEADERS', 'true')
      incoming.headers = new Headers({ 'x-forwarded-for': '203.0.113.7, not-an-ip' })
      expect(await browserContextHeaders()).toEqual({})
    })
  })

  it('returns nothing outside a request', async () => {
    vi.resetModules()
    vi.doMock('next/headers', () => ({
      headers: async () => {
        throw new Error('outside a request')
      },
    }))
    const mod = await import('@/lib/api/browser-context-headers')
    expect(await mod.browserContextHeaders()).toEqual({})
    vi.doUnmock('next/headers')
  })
})
