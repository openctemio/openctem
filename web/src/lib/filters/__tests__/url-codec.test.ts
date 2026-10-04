import { describe, expect, it } from 'vitest'

import { findingsHref, joinList, migrateLegacyParams } from '../url-codec'

const SORT = {
  severity: { api: 'severity', invert: true },
  createdAt: { api: 'created_at' },
}

function migrate(qs: string) {
  const out = migrateLegacyParams(new URLSearchParams(qs), undefined, SORT)
  return out ? out.toString() : null
}

describe('migrateLegacyParams', () => {
  it('leaves current links alone', () => {
    expect(migrate('severity=critical&is_in_kev=true&q=log4j&sort=-created_at')).toBeNull()
  })

  it('rewrites the old page vocabulary to the API names', () => {
    const out = new URLSearchParams(
      migrate('assetId=a1&sources=sast,dast&priority=p0&kev=true&reachable=false&mine=true&cve=CVE-1&rule=r1')!
    )
    expect(out.get('asset_id')).toBe('a1')
    expect(out.get('source')).toBe('sast,dast')
    expect(out.get('priority_class')).toBe('P0')
    expect(out.get('is_in_kev')).toBe('true')
    expect(out.has('is_reachable')).toBe(false)
    expect(out.get('related_to')).toBe('me')
    expect(out.get('cve_id')).toBe('CVE-1')
    expect(out.get('rule_id')).toBe('r1')
    for (const old of ['assetId', 'sources', 'priority', 'kev', 'reachable', 'mine', 'cve', 'rule']) {
      expect(out.has(old)).toBe(false)
    }
  })

  it('folds priority=kev/reachable into the flags', () => {
    const out = new URLSearchParams(migrate('priority=kev,P1,reachable')!)
    expect(out.get('is_in_kev')).toBe('true')
    expect(out.get('is_reachable')).toBe('true')
    expect(out.get('priority_class')).toBe('P1')
  })

  it('drops a data-source id the API never read', () => {
    expect(migrate('source=11111111-2222-3333-4444-555555555555')).toBe('')
    expect(migrate('source=sast')).toBeNull()
  })

  it('converts a legacy table sort', () => {
    expect(new URLSearchParams(migrate('sort=severity.desc')!).get('sort')).toBe('severity')
    expect(new URLSearchParams(migrate('sort=createdAt.desc')!).get('sort')).toBe('-created_at')
    expect(new URLSearchParams(migrate('sort=bogus.asc')!).has('sort')).toBe(false)
  })

  it('merges an alias into a param already present', () => {
    expect(new URLSearchParams(migrate('source=sast&sources=dast,sast')!).get('source')).toBe('sast,dast')
  })
})

describe('findingsHref', () => {
  it('builds API-named links', () => {
    expect(findingsHref({ related_to: 'me', priority_class: ['P0'] })).toBe('/findings?related_to=me&priority_class=P0')
    expect(findingsHref({ asset_id: 'a', is_in_kev: false, q: '' })).toBe('/findings?asset_id=a')
    expect(findingsHref({})).toBe('/findings')
  })
  it('joins lists without empties or "all"', () => {
    expect(joinList(['a', '', 'all', 'a', 'b'])).toBe('a,b')
    expect(joinList([])).toBeUndefined()
  })
})
