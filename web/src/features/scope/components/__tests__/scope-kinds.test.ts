import { describe, expect, it } from 'vitest'
import {
  detectScopeKind,
  scopeKindOf,
  scopeTargetTypeLabel,
  SCOPE_KINDS,
  storedTypesFor,
} from '../scope-target-type'
import { defaultCoverage } from '../scope-entry-dialog'

// research/53 SC4: six kinds, detected from the pattern; no "subdomain".
describe('scope kinds', () => {
  it('has six kinds and no subdomain', () => {
    expect(SCOPE_KINDS).toEqual([
      'domain',
      'ip_address',
      'ip_range',
      'url',
      'repository',
      'cloud_account',
    ])
    expect(SCOPE_KINDS).not.toContain('subdomain')
  })

  it.each([
    ['example.com', 'domain'],
    ['*.vndirect.com.vn', 'domain'],
    ['api.dev.acme.io', 'domain'],
    ['203.0.113.7', 'ip_address'],
    ['2001:db8::1', 'ip_address'],
    ['203.0.113.0/24', 'ip_range'],
    ['203.0.113.10-203.0.113.20', 'ip_range'],
    ['https://app.acme.io/portal', 'url'],
    ['github.com/acme/web', 'repository'],
    ['AWS:123456789012', 'cloud_account'],
  ])('detects %s as %s', (pattern, kind) => {
    expect(detectScopeKind(pattern)).toBe(kind)
  })

  it.each(['', 'not a pattern', 'localhost', '999.1.1.1/99'])('cannot tell %j', (pattern) => {
    expect(detectScopeKind(pattern)).toBeUndefined()
  })

  it('reads older stored types as their kind, so *.x is never "Subdomain"', () => {
    expect(scopeTargetTypeLabel('subdomain')).toBe('Domain')
    expect(scopeTargetTypeLabel('cidr')).toBe('IP range')
    expect(scopeKindOf('website')).toBe('url')
    expect(storedTypesFor('domain').split(',')).toContain('subdomain')
    expect(storedTypesFor('domain', 'exclusions')).toBe('domain,subdomain')
    expect(storedTypesFor('ip_range', 'exclusions')).toBe('ip_range,cidr')
  })

  it('defaults coverage by depth: a registrable domain covers below it, a host only itself', () => {
    expect(defaultCoverage('ipas.com.vn')).toBe('subdomains')
    expect(defaultCoverage('acme.io')).toBe('subdomains')
    expect(defaultCoverage('api.ipas.com.vn')).toBe('name')
  })
})
