import { describe, expect, it } from 'vitest'

import { buildCsp, cspForRequest, generateNonce, isCaptchaRoute, TURNSTILE_ORIGIN } from '../csp'

function directive(policy: string, name: string): string[] {
  const found = policy
    .split(';')
    .map((d) => d.trim())
    .find((d) => d.startsWith(`${name} `))
  return found ? found.split(/\s+/).slice(1) : []
}

describe('buildCsp', () => {
  const prod = buildCsp({ nonce: 'abc123', isDev: false })
  const dev = buildCsp({ nonce: 'abc123', isDev: true })

  it("has no 'unsafe-inline' for scripts, in production or dev", () => {
    expect(directive(prod, 'script-src')).not.toContain("'unsafe-inline'")
    expect(directive(dev, 'script-src')).not.toContain("'unsafe-inline'")
  })

  it('allows scripts by nonce with strict-dynamic', () => {
    expect(directive(prod, 'script-src')).toEqual(
      expect.arrayContaining(["'nonce-abc123'", "'strict-dynamic'"])
    )
  })

  it("allows 'unsafe-eval' only in dev (HMR)", () => {
    expect(directive(prod, 'script-src')).not.toContain("'unsafe-eval'")
    expect(directive(dev, 'script-src')).toContain("'unsafe-eval'")
  })

  it('locks plugins, framing, base and forms', () => {
    expect(directive(prod, 'object-src')).toEqual(["'none'"])
    expect(directive(prod, 'frame-ancestors')).toEqual(["'none'"])
    expect(directive(prod, 'base-uri')).toEqual(["'self'"])
    expect(directive(prod, 'form-action')).toEqual(["'self'"])
  })

  it('derives connect-src from the configured origins in production', () => {
    const p = buildCsp({
      nonce: 'n',
      isDev: false,
      appUrl: 'https://ctem.example.com',
      backendUrl: 'http://api:8080',
      wsUrl: 'https://ws.example.com:9090',
    })
    expect(directive(p, 'connect-src')).toEqual([
      "'self'",
      'https://ctem.example.com',
      'wss://ctem.example.com',
      'https://ctem.example.com:8080',
      'wss://ctem.example.com:8080',
      'wss://ws.example.com:9090',
      'https://ws.example.com:9090',
    ])
  })
})

describe('generateNonce', () => {
  it('is 128 bits of base64 and different every time', () => {
    const a = generateNonce()
    const b = generateNonce()
    expect(a).toMatch(/^[A-Za-z0-9+/]{22}==$/)
    expect(a).not.toBe(b)
  })
})

describe('CAPTCHA pages', () => {
  it('only the CAPTCHA routes allow the Turnstile origin', () => {
    expect(isCaptchaRoute('/request-access')).toBe(true)
    expect(isCaptchaRoute('/request-access/confirm')).toBe(true)
    expect(isCaptchaRoute('/register')).toBe(true)
    expect(isCaptchaRoute('/login')).toBe(false)
    expect(isCaptchaRoute('/request-accessx')).toBe(false)
    expect(isCaptchaRoute('/settings')).toBe(false)
    expect(isCaptchaRoute('/')).toBe(false)
  })

  it('adds the Turnstile origin to script, frame and connect on a CAPTCHA page, keeping the nonce', () => {
    const p = cspForRequest('n1', '/request-access')
    expect(directive(p, 'script-src')).toEqual(
      expect.arrayContaining(["'nonce-n1'", "'strict-dynamic'", TURNSTILE_ORIGIN])
    )
    expect(directive(p, 'script-src')).not.toContain("'unsafe-inline'")
    expect(directive(p, 'frame-src')).toEqual([TURNSTILE_ORIGIN])
    expect(directive(p, 'connect-src')).toContain(TURNSTILE_ORIGIN)
    expect(directive(p, 'frame-ancestors')).toEqual(["'none'"])
  })

  it('no other page allows it', () => {
    for (const path of ['/login', '/', '/settings/plan', '/admin/system/plans', '']) {
      const p = cspForRequest('n1', path)
      expect(p).not.toContain('challenges.cloudflare.com')
      expect(directive(p, 'frame-src')).toEqual(["'none'"])
    }
  })
})
