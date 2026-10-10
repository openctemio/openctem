import { describe, expect, it } from 'vitest'
import { classifyTarget, parsePastedTargets } from '../target-format'

describe('classifyTarget', () => {
  it.each([
    ['example.com', 'domain', 'example.com'],
    ['API.Example.COM.', 'domain', 'api.example.com'],
    ['*.example.com', 'wildcard', '*.example.com'],
    ['192.0.2.10', 'ipv4', '192.0.2.10'],
    ['10.0.0.0/8', 'cidr', '10.0.0.0/8'],
    ['2001:db8::1', 'ipv6', '2001:db8::1'],
    ['2001:db8::/32', 'cidr', '2001:db8::/32'],
    ['https://app.example.com/login#top', 'url', 'https://app.example.com/login#top'],
    ['mail.example.com:587', 'host:port', 'mail.example.com:587'],
  ])('%s is a %s', (input, kind, value) => {
    expect(classifyTarget(input)).toMatchObject({ kind, value })
  })

  it.each([
    ['example', 'Not a domain'],
    ['*.com', 'wildcard'],
    ['300.1.1.1', 'Not a domain'],
    ['10.0.0.0/33', 'CIDR'],
    ['host.example.com:70000', 'host:port'],
    ['example.com; rm -rf /', 'characters'],
    ['$(whoami).example.com', 'characters'],
  ])('%s is invalid (%s)', (input, reason) => {
    const c = classifyTarget(input)
    expect(c.kind).toBe('invalid')
    expect(c.reason).toMatch(new RegExp(reason, 'i'))
  })

  it('decides nothing about scope: private addresses are just addresses', () => {
    expect(classifyTarget('192.168.1.10').kind).toBe('ipv4')
    expect(classifyTarget('localhost:8080').kind).toBe('host:port')
  })
})

describe('parsePastedTargets', () => {
  it('normalizes, removes repeats and counts each kind', () => {
    const p = parsePastedTargets([
      'Example.com',
      'example.com.',
      '',
      'b@d',
      '10.0.0.1',
      ' 10.0.0.1 ',
    ])
    expect(p.targets).toEqual(['example.com', '10.0.0.1'])
    expect(p.duplicates).toBe(2)
    expect(p.invalid.map((i) => i.input)).toEqual(['b@d'])
    expect(p.byKind).toEqual({ domain: 2, invalid: 1, ipv4: 2 })
  })
})

describe('pasted lists', () => {
  it('splits on commas, semicolons and spaces', () => {
    expect(
      parsePastedTargets(['a.example.com, b.example.com;c.example.com d.example.com']).targets
    ).toEqual(['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'])
  })
})
