import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'

import { buildCsp, cspForRequest, generateNonce } from '../csp'

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

  it('loads fonts and styles from our own origin only (self-hosted fonts, no CDN)', () => {
    expect(directive(prod, 'font-src')).toEqual(["'self'", 'data:'])
    for (const d of ['style-src', 'style-src-elem'])
      expect(directive(prod, d).filter((s) => s.startsWith('http'))).toEqual([])
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

describe('cspForRequest', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it("uses the running server's NEXT_PUBLIC_APP_URL", () => {
    vi.stubEnv('NODE_ENV', 'production')
    vi.stubEnv('NEXT_PUBLIC_APP_URL', 'https://ctem.customer.example')
    vi.stubEnv('BACKEND_API_URL', 'http://api:8080')
    vi.stubEnv('NEXT_PUBLIC_WS_BASE_URL', '')
    expect(directive(cspForRequest('n'), 'connect-src')).toContain('https://ctem.customer.example')
  })

  // A literal process.env.NEXT_PUBLIC_* is inlined at build time: a published
  // image would put the build's origin into every deployment's policy.
  it('reads the origins through a computed key, never a build-time literal', () => {
    const src = readFileSync(join(__dirname, '..', 'csp.ts'), 'utf8')
    expect(src).not.toMatch(/process\.env\.NEXT_PUBLIC_(APP_URL|WS_BASE_URL)/)
  })
})
