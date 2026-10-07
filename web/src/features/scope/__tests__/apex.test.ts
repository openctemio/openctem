import { describe, expect, it } from 'vitest'
import { wildcardApex } from '../lib/apex'

describe('wildcardApex', () => {
  it('returns the apex of a domain wildcard', () => {
    expect(wildcardApex('domain', '*.x.com')).toBe('x.com')
    expect(wildcardApex('domain', '**.x.com.')).toBe('x.com')
  })
  it('returns null for plain domains, other types and odd input', () => {
    expect(wildcardApex('domain', 'x.com')).toBeNull()
    expect(wildcardApex('ip_range', '*.x.com')).toBeNull()
    expect(wildcardApex('domain', '*.*.x.com')).toBeNull()
    expect(wildcardApex('domain', '*.')).toBeNull()
    expect(wildcardApex(undefined, '*.x.com')).toBeNull()
  })
})
