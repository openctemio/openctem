import { describe, expect, it } from 'vitest'
import { hostOf, matchDomain } from '../scope-matcher'

// The web matcher must agree with the API (RFC-054 §4.1, research/63 PR0).
describe('hostOf', () => {
  it.each([
    ['vndirect.com.vn:443:tcp', 'vndirect.com.vn'],
    ['vndirect.com.vn:443/tcp', 'vndirect.com.vn'],
    ['https://Shop.Vndirect.com.vn/x', 'shop.vndirect.com.vn'],
    ['vndirect.com.vn:8443/admin', 'vndirect.com.vn'],
    ['Vndirect.com.vn.', 'vndirect.com.vn'],
    ['[2001:db8::1]:443/tcp', '2001:db8::1'],
    ['2001:db8::1:443:tcp', '2001:db8::1'],
    ['2001:db8::1', '2001:db8::1'],
    ['203.0.113.0/24', '203.0.113.0/24'],
    ['10.0.0.5:22:tcp', '10.0.0.5'],
  ])('%s -> %s', (input, want) => {
    expect(hostOf(input)).toBe(want)
  })
})

describe('matchDomain', () => {
  it('a wildcard covers its apex and every name below it', () => {
    expect(matchDomain('*.vndirect.com.vn', 'vndirect.com.vn')).toBe(true)
    expect(matchDomain('*.vndirect.com.vn', 'a.b.vndirect.com.vn')).toBe(true)
    expect(matchDomain('**.vndirect.com.vn', 'vndirect.com.vn.')).toBe(true)
    expect(matchDomain('*.vndirect.com.vn', 'vndirect.com.vn:443:tcp')).toBe(true)
    expect(matchDomain('*.vndirect.com.vn', 'https://app.vndirect.com.vn/login')).toBe(true)
  })
  it('an exact pattern is only that name', () => {
    expect(matchDomain('vndirect.com.vn', 'VNDIRECT.com.vn')).toBe(true)
    expect(matchDomain('vndirect.com.vn', 'app.vndirect.com.vn')).toBe(false)
  })
  it('look-alikes do not match', () => {
    expect(matchDomain('*.vndirect.com.vn', 'evilvndirect.com.vn')).toBe(false)
    expect(matchDomain('*.vndirect.com.vn', 'vndirect.com.vn.evil.net')).toBe(false)
  })
})
