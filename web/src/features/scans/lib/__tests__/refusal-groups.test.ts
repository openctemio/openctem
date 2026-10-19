import { describe, expect, it } from 'vitest'
import { groupRefusals, internalAddressOf, ownSensorHelps, canVerify } from '../refusal-groups'

const proof = (target: string, root: string) => ({
  target,
  allowed: false,
  code: 'proof_required',
  fixes: [{ action: 'verify_domain', domain: root }, { action: 'use_tenant_sensor' }],
})
const zone = (target: string, resolved?: string[]) => ({
  target,
  allowed: false,
  code: 'zone_none',
  resolved,
})

describe('groupRefusals', () => {
  it('groups 281 refusals into a few decisions, one per reason, with counts', () => {
    const results = [
      ...Array.from({ length: 212 }, (_, i) => proof(`h${i}.vndirect.com.vn`, 'vndirect.com.vn')),
      ...Array.from({ length: 69 }, (_, i) => zone(`int${i}.vndirect.com.vn`, ['10.0.0.1'])),
      { target: 'ok.example', allowed: true },
      { target: 'other.example', allowed: false, code: 'no_entry' },
    ]
    const groups = groupRefusals(results)
    expect(groups.map((g) => [g.kind, g.results.length])).toEqual([
      ['proof', 212],
      ['zone', 69],
      ['scope', 1],
    ])
    expect(groups[0].domains).toEqual(['vndirect.com.vn'])
    expect(canVerify(groups[0])).toBe(true)
    expect(ownSensorHelps(groups[0])).toBe(true)
    expect(ownSensorHelps(groups[1])).toBe(false)
  })

  it('groups entry refusals per covering entry, with its one-shot fix, first', () => {
    const groups = groupRefusals([
      { target: 'a.x.io', allowed: false, code: 'no_entry' },
      {
        target: 'a.vn',
        allowed: false,
        code: 'entry_pending',
        rule: { id: 'e1', pattern: '*.vn' },
        fixes: [{ action: 'approve_entry', id: 'e1' }],
      },
      {
        target: 'b.vn',
        allowed: false,
        code: 'entry_pending',
        rule: { id: 'e1', pattern: '*.vn' },
      },
      {
        target: 'c.off',
        allowed: false,
        code: 'entry_inactive',
        rule: { id: 'e2', pattern: 'c.off' },
        fixes: [{ action: 'activate_entry', id: 'e2' }],
      },
    ])
    expect(groups[0].key).toBe('entry:e1')
    expect(groups[0].results).toHaveLength(2)
    expect(groups[0].fixes).toEqual([{ action: 'approve_entry', id: 'e1' }])
    expect(groups[1].key).toBe('entry:e2')
    expect(groups.at(-1)?.kind).toBe('scope')
  })

  it('does not offer the own sensor when the server did not (intrusive proof)', () => {
    const [g] = groupRefusals([
      {
        target: 'x.io',
        allowed: false,
        code: 'proof_required',
        fixes: [{ action: 'verify_domain', domain: 'x.io' }],
      },
    ])
    expect(ownSensorHelps(g)).toBe(false)
  })
})

describe('internalAddressOf', () => {
  it('names what a hostname resolved to, or the address itself', () => {
    expect(internalAddressOf(zone('intra.acme.io', ['10.20.0.7', '10.20.0.8']))).toBe('10.20.0.7')
    expect(internalAddressOf(zone('192.168.1.4'))).toBe('192.168.1.4')
    expect(internalAddressOf(zone('fd00::1'))).toBe('fd00::1')
    expect(internalAddressOf(zone('intra.acme.io'))).toBeUndefined()
  })

  it('puts a name that does not resolve in its own group, apart from private addresses', () => {
    const groups = groupRefusals([
      { target: 'gone.example.com', allowed: false, code: 'unresolved' },
      zone('intra.example.com', ['10.0.0.1']),
    ])
    expect(groups.map((g) => g.kind)).toEqual(['zone', 'unresolved'])
  })
})
