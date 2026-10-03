import { describe, expect, it } from 'vitest'

import { buildCsp, generateNonce } from '../csp'

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
