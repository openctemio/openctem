import { describe, expect, it } from 'vitest'
import {
  domainRoot,
  domainRoots,
  expandTargets,
  isBelow,
  MAX_EXPANDED_TARGETS,
  resolvedIps,
} from '../coverage-expansion'

const inventory = [
  { name: 'acme.io', properties: { resolved_ips: ['203.0.113.1'] } },
  { name: 'api.acme.io', properties: { resolved_ips: ['203.0.113.2', '203.0.113.1'] } },
  { name: 'deep.dev.acme.io' },
  { name: 'notacme.io', properties: { resolved_ips: ['198.51.100.9'] } },
  { name: 'acme.io.evil.net' },
  { name: '203.0.113.50' },
]

describe('coverage level expansion', () => {
  it('this host only adds nothing', () => {
    expect(expandTargets(['acme.io'], 'host', inventory)).toEqual([])
  })

  it('lists no subdomains: *.domain covers them at every run (RFC-068)', () => {
    expect(expandTargets(['acme.io'], 'subdomains', inventory)).toEqual([])
  })

  it('adds the addresses those names resolved to, once each, never look-alikes', () => {
    expect(expandTargets(['https://acme.io/login'], 'subdomains_ips', inventory)).toEqual([
      '203.0.113.1',
      '203.0.113.2',
    ])
  })

  it('never repeats a typed target and caps the result', () => {
    expect(expandTargets(['acme.io', '203.0.113.1'], 'subdomains_ips', inventory)).toEqual([
      '203.0.113.2',
    ])
    const many = Array.from({ length: 600 }, (_, i) => ({
      name: `h${i}.acme.io`,
      properties: { resolved_ips: [`10.0.${Math.floor(i / 250)}.${i % 250}`] },
    }))
    expect(expandTargets(['acme.io'], 'subdomains_ips', many)).toHaveLength(MAX_EXPANDED_TARGETS)
  })

  it('reads only DNS names as roots', () => {
    expect(domainRoot('*.Acme.IO.')).toBe('acme.io')
    expect(domainRoot('acme.io:8443')).toBe('acme.io')
    expect(domainRoot('203.0.113.7')).toBe('')
    expect(domainRoot('2001:db8::1')).toBe('')
    expect(domainRoots(['a.acme.io', 'acme.io', 'x.org'])).toEqual(['x.org', 'acme.io'])
    expect(isBelow('acme.io', 'acme.io')).toBe(false)
  })

  it('ignores malformed resolved_ips', () => {
    expect(resolvedIps({ resolved_ips: ['1.2.3.4', 5, ''] })).toEqual(['1.2.3.4'])
    expect(resolvedIps({ resolved_ips: 'x' })).toEqual([])
  })
})
