import { describe, expect, it } from 'vitest'
import type { ApiScopeCheckResult } from '@/features/scope'
import { groupRefusals, groupRemedy, internalAddressOf } from '../refusal-groups'

const proof = (target: string, root: string): ApiScopeCheckResult => ({
  target,
  allowed: false,
  code: 'proof_required',
  fixes: [{ action: 'verify_domain', domain: root }, { action: 'use_tenant_sensor' }],
  remedies: [
    { action: 'run_on_tenant_sensor' },
    { action: 'verify_domain', domain: root },
    { action: 'remove' },
  ],
})
const zone = (target: string, resolved?: string[]): ApiScopeCheckResult => ({
  target,
  allowed: false,
  code: 'zone_none',
  resolved,
  remedies: [{ action: 'remove' }],
})

describe('groupRefusals', () => {
  it('groups 281 refusals into a few decisions, one per reason, with counts', () => {
    const results = [
      ...Array.from({ length: 212 }, (_, i) => proof(`h${i}.example.com`, 'example.com')),
      ...Array.from({ length: 69 }, (_, i) => zone(`int${i}.example.com`, ['10.0.0.1'])),
      { target: 'ok.example', allowed: true },
      { target: 'other.example', allowed: false, code: 'no_entry' },
    ]
    const groups = groupRefusals(results)
    expect(groups.map((g) => [g.kind, g.results.length])).toEqual([
      ['proof', 212],
      ['zone', 69],
      ['scope', 1],
    ])
    expect(groups[0].domains).toEqual(['example.com'])
    expect(groups[0].remedies.map((r) => r.action)).toEqual([
      'run_on_tenant_sensor',
      'verify_domain',
      'remove',
    ])
    expect(groupRemedy(groups[0], 'verify_domain')?.domains).toEqual(['example.com'])
    expect(groupRemedy(groups[1], 'run_on_tenant_sensor')).toBeUndefined()
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

  it('does not offer the own sensor when the server did not', () => {
    const [g] = groupRefusals([
      {
        target: 'x.io',
        allowed: false,
        code: 'proof_required',
        remedies: [{ action: 'verify_domain', domain: 'x.io' }, { action: 'remove' }],
      },
    ])
    expect(groupRemedy(g, 'run_on_tenant_sensor')).toBeUndefined()
  })

  it('merges members in the server order, remove last, the lowest tier to lower to', () => {
    const [g] = groupRefusals([
      {
        target: 'a.io',
        allowed: false,
        code: 'tier_exceeds',
        remedies: [{ action: 'remove' }],
      },
      {
        target: 'b.io',
        allowed: false,
        code: 'tier_exceeds',
        remedies: [{ action: 'lower_intensity', tier: 1 }, { action: 'remove' }],
      },
      {
        target: 'c.io',
        allowed: false,
        code: 'tier_exceeds',
        remedies: [{ action: 'lower_intensity', tier: 0 }, { action: 'remove' }],
      },
      {
        target: 'd.io',
        allowed: false,
        code: 'tier_exceeds',
        remedies: [{ action: 'bogus' as never }],
      },
    ])
    expect(g.remedies.map((r) => r.action)).toEqual(['lower_intensity', 'remove'])
    expect(groupRemedy(g, 'lower_intensity')?.tier).toBe(0)
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
