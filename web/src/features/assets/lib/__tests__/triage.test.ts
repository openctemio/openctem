import { describe, expect, it } from 'vitest'
import { exactExclusions, ruleProposals } from '../out-of-scope-rules'
import { triagePresets } from '../inventory-facets'
import { nextVisits } from '../../hooks/use-last-visit'

describe('out-of-scope rules', () => {
  it('maps names to exact exclusions and skips what needs none', () => {
    const r = exactExclusions([
      'a.example.com',
      'https://a.example.com/x',
      '203.0.113.9',
      '10.0.0.1',
    ])
    expect(r.items).toEqual([
      { exclusion_type: 'domain', pattern: 'a.example.com' },
      { exclusion_type: 'ip_address', pattern: '203.0.113.9' },
    ])
    expect(r.skipped).toBe(1)
  })

  it('proposes parent wildcards and /24s, never a bare top-level domain', () => {
    const r = ruleProposals([
      'a.x.example.com',
      'b.x.example.com',
      'example.com',
      'host.com',
      '198.51.100.7',
    ])
    expect(r.map((p) => p.item.pattern)).toEqual(['*.x.example.com', '198.51.100.0/24'])
    expect(r[0].covers).toBe(2)
  })
})

describe('triage views', () => {
  it('uses the last visit, else the last 7 days', () => {
    const now = Date.parse('2026-10-13T00:00:00Z')
    const since = triagePresets(undefined, now).find((p) => p.id === 'new-since-visit')!
    expect(since.apply.firstSeenAfter).toBe('2026-10-06T00:00:00.000Z')
    const visited = triagePresets('2026-10-12T08:00:00.000Z', now).find(
      (p) => p.id === 'new-since-visit'
    )!
    expect(visited.apply.firstSeenAfter).toBe('2026-10-12T08:00:00.000Z')
    const out = triagePresets(undefined, now).find((p) => p.id === 'out-of-scope')!
    expect(out.apply).toEqual({ scopeStatus: ['excluded'], attribution: ['all'] })
  })

  it('keeps the previous visit within one session', () => {
    const t0 = new Date('2026-10-13T08:00:00Z')
    const first = nextVisits(null, t0)
    expect(first.previous).toBeUndefined()
    expect(nextVisits(first, new Date('2026-10-13T08:10:00Z'))).toEqual(first)
    expect(nextVisits(first, new Date('2026-10-13T12:00:00Z')).previous).toBe(t0.toISOString())
  })
})
