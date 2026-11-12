import { describe, expect, it } from 'vitest'
import { expiresInDays, scopeEntryTarget } from '../scope-pick'

describe('scopeEntryTarget', () => {
  it('a wildcard entry becomes a *.domain target', () => {
    expect(scopeEntryTarget({ pattern: '*.Example.com' })).toBe('*.example.com')
    expect(scopeEntryTarget({ pattern: '**.example.com' })).toBe('*.example.com')
  })

  it('a domain covering its subdomains becomes its wildcard; a name stays a name', () => {
    expect(scopeEntryTarget({ pattern: 'example.com', covers: 'domain_and_subdomains' })).toBe(
      '*.example.com'
    )
    expect(scopeEntryTarget({ pattern: 'app.example.com', covers: 'name' })).toBe('app.example.com')
  })

  it('an address or a CIDR is itself', () => {
    expect(scopeEntryTarget({ pattern: '203.0.113.7' })).toBe('203.0.113.7')
    expect(scopeEntryTarget({ pattern: '203.0.113.0/24' })).toBe('203.0.113.0/24')
  })

  it('a name pattern or an address span is not one target', () => {
    expect(scopeEntryTarget({ pattern: 'api-*.example.com' })).toBeNull()
    expect(scopeEntryTarget({ pattern: '203.0.113.1-203.0.113.9' })).toBeNull()
    expect(scopeEntryTarget({ pattern: '' })).toBeNull()
  })
})

describe('expiresInDays', () => {
  const now = Date.parse('2026-11-04T00:00:00Z')
  it('counts whole days left, null for a permanent entry', () => {
    expect(expiresInDays(undefined, now)).toBeNull()
    expect(expiresInDays('2026-11-06T12:00:00Z', now)).toBe(3)
    expect(expiresInDays('2026-11-03T00:00:00Z', now)).toBe(0)
  })
})
