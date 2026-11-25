import { describe, it, expect, afterEach, vi } from 'vitest'

import {
  applyClientIpHeaders,
  clientIpHeaders,
  parseIpAddress,
  proxiedClientAddress,
  trustProxyHeaders,
} from '@/lib/api/client-ip-headers'

// The request as the web server receives it: a value the caller wrote on the
// left, the entry the proxy in front of this server added on the right.
const chained = () =>
  new Headers({
    'x-real-ip': '203.0.113.7',
    'x-forwarded-for': '203.0.113.7, 198.51.100.20',
    'user-agent': 'test',
  })

describe('trustProxyHeaders', () => {
  afterEach(() => vi.unstubAllEnvs())

  it('is off unless TRUST_PROXY_HEADERS is exactly "true"', () => {
    expect(trustProxyHeaders(undefined)).toBe(false)
    expect(trustProxyHeaders('')).toBe(false)
    expect(trustProxyHeaders('1')).toBe(false)
    expect(trustProxyHeaders('TRUE')).toBe(false)
    expect(trustProxyHeaders('true')).toBe(true)
  })

  it('reads the env var by default', () => {
    vi.stubEnv('TRUST_PROXY_HEADERS', 'true')
    expect(trustProxyHeaders()).toBe(true)
    vi.stubEnv('TRUST_PROXY_HEADERS', 'false')
    expect(trustProxyHeaders()).toBe(false)
  })
})

describe('parseIpAddress', () => {
  it('accepts bare IPv4 and IPv6 addresses', () => {
    expect(parseIpAddress(' 198.51.100.20 ')).toBe('198.51.100.20')
    expect(parseIpAddress('2001:db8::1')).toBe('2001:db8::1')
    expect(parseIpAddress('2001:DB8:0:0:0:0:0:1')).toBe('2001:db8::1')
  })

  it('refuses anything that is not a bare address', () => {
    for (const bad of [
      '',
      'unknown',
      '198.51.100.256',
      '198.51.100.20:443',
      '01.2.3.4',
      'example.com',
      '[2001:db8::1]',
      '2001:db8::1%eth0',
      '1.2.3.4 5.6.7.8',
      null,
      undefined,
    ]) {
      expect(parseIpAddress(bad)).toBeNull()
    }
  })
})

describe('proxiedClientAddress', () => {
  it('takes the right-most X-Forwarded-For entry and ignores the ones to its left', () => {
    expect(proxiedClientAddress(chained())).toBe('198.51.100.20')
  })

  it('treats several X-Forwarded-For lines as one list', () => {
    const h = new Headers()
    h.append('x-forwarded-for', '203.0.113.7')
    h.append('x-forwarded-for', '198.51.100.20')
    expect(proxiedClientAddress(h)).toBe('198.51.100.20')
  })

  it('returns nothing when the right-most entry is malformed (no fallback to the left)', () => {
    expect(
      proxiedClientAddress(new Headers({ 'x-forwarded-for': '203.0.113.7, garbage' }))
    ).toBeNull()
    expect(proxiedClientAddress(new Headers({ 'x-forwarded-for': '203.0.113.7,' }))).toBeNull()
  })

  it('uses X-Real-IP only when X-Forwarded-For is absent', () => {
    expect(proxiedClientAddress(new Headers({ 'x-real-ip': '198.51.100.20' }))).toBe(
      '198.51.100.20'
    )
    expect(
      proxiedClientAddress(
        new Headers({ 'x-real-ip': '203.0.113.7', 'x-forwarded-for': 'garbage' })
      )
    ).toBeNull()
  })
})

describe('clientIpHeaders', () => {
  afterEach(() => vi.unstubAllEnvs())

  it('forwards nothing when the proxy is not trusted, whatever the request says', () => {
    expect(clientIpHeaders(chained(), false)).toEqual([])
    expect(clientIpHeaders(new Headers({ 'x-forwarded-for': '203.0.113.7' }), false)).toEqual([])
    expect(clientIpHeaders(new Headers({ 'x-real-ip': '203.0.113.7' }), false)).toEqual([])
  })

  it('forwards the one derived address in both headers when trusted', () => {
    expect(clientIpHeaders(chained(), true)).toEqual([
      ['x-real-ip', '198.51.100.20'],
      ['x-forwarded-for', '198.51.100.20'],
    ])
  })

  it('a value added in front of the trusted entry does not change what is forwarded', () => {
    const plain = clientIpHeaders(new Headers({ 'x-forwarded-for': '198.51.100.20' }), true)
    const prefixed = clientIpHeaders(
      new Headers({ 'x-forwarded-for': '192.0.2.1, 192.0.2.2, 198.51.100.20' }),
      true
    )
    expect(prefixed).toEqual(plain)
  })

  it('skips headers that are absent, blank or malformed', () => {
    expect(clientIpHeaders(new Headers({ 'x-forwarded-for': '  ' }), true)).toEqual([])
    expect(clientIpHeaders(new Headers({ 'x-forwarded-for': 'nope' }), true)).toEqual([])
    expect(clientIpHeaders(new Headers(), true)).toEqual([])
  })

  it('defaults to the env var: off when unset', () => {
    vi.stubEnv('TRUST_PROXY_HEADERS', '')
    expect(clientIpHeaders(chained())).toEqual([])
  })
})

describe('applyClientIpHeaders', () => {
  it('sets only the client-IP headers on the outgoing request', () => {
    const out = new Headers({ 'content-type': 'application/json' })
    applyClientIpHeaders(out, chained(), true)
    expect(out.get('x-real-ip')).toBe('198.51.100.20')
    expect(out.get('x-forwarded-for')).toBe('198.51.100.20')
    expect(out.get('user-agent')).toBeNull()
  })

  it('leaves no client-IP header on the outgoing request when untrusted', () => {
    const out = new Headers({ 'x-forwarded-for': '203.0.113.7' })
    applyClientIpHeaders(out, chained(), false)
    expect(out.get('x-real-ip')).toBeNull()
    expect(out.get('x-forwarded-for')).toBeNull()
  })
})
