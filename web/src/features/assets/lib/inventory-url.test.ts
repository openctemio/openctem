import { describe, it, expect } from 'vitest'
import {
  attributionQuery,
  countActiveFilters,
  DEFAULT_PAGE_SIZE,
  isInventoryFilterEmpty,
  parseInventoryFilters,
  serializeInventoryFilters,
  sortingToSort,
  sortToSorting,
  togglePropertyFilter,
  type InventoryFilters,
} from './inventory-url'

describe('inventory URL codec', () => {
  it('round-trips every kind of filter through the query string', () => {
    const filters: InventoryFilters = {
      search: 'web',
      types: ['host', 'domain'],
      criticalities: ['critical'],
      hasOwner: false,
      isInternetAccessible: true,
      lastSeenBefore: '2026-01-01T00:00:00.000Z',
      sort: '-risk_score',
      page: 3,
      pageSize: 50,
    }
    const qs = serializeInventoryFilters(filters)
    expect(qs.get('types')).toBe('host,domain')
    expect(qs.get('has_owner')).toBe('false')
    expect(parseInventoryFilters(qs)).toEqual(filters)
  })

  it('round-trips the expiry range and counts it once', () => {
    const filters: InventoryFilters = {
      expiresAfter: '2026-10-08T00:00:00.000Z',
      expiresBefore: '2026-11-07T00:00:00.000Z',
    }
    const qs = serializeInventoryFilters(filters)
    expect(qs.get('expires_after')).toBe('2026-10-08T00:00:00.000Z')
    expect(parseInventoryFilters(qs)).toEqual(filters)
    expect(countActiveFilters(filters)).toBe(1)
    expect(isInventoryFilterEmpty(filters)).toBe(false)
  })

  it('round-trips the lens and the minimum risk score', () => {
    const filters: InventoryFilters = { lens: 'code', minRiskScore: 70 }
    const qs = serializeInventoryFilters(filters)
    expect(qs.toString()).toBe('lens=code&min_risk_score=70')
    expect(parseInventoryFilters(qs)).toEqual(filters)
    expect(countActiveFilters(filters)).toBe(2)
    expect(isInventoryFilterEmpty(filters)).toBe(false)
  })

  it('drops an unknown lens and an out-of-range risk score', () => {
    for (const qs of ['lens=nope', 'min_risk_score=101', 'min_risk_score=-1', 'min_risk_score=x']) {
      expect(parseInventoryFilters(new URLSearchParams(qs))).toEqual({})
    }
    expect(parseInventoryFilters(new URLSearchParams('min_risk_score=0'))).toEqual({
      minRiskScore: 0,
    })
  })

  it('omits page 1 and the default page size from the URL', () => {
    const qs = serializeInventoryFilters({ page: 1, pageSize: DEFAULT_PAGE_SIZE })
    expect(qs.toString()).toBe('')
  })

  it('counts each selected value, each boolean and the search', () => {
    const f: InventoryFilters = { types: ['host', 'domain'], hasOwner: false, search: 'x' }
    expect(countActiveFilters(f)).toBe(4)
    expect(isInventoryFilterEmpty(f)).toBe(false)
    expect(isInventoryFilterEmpty({ sort: 'name', page: 2, pageSize: 50 })).toBe(true)
  })
})

describe('inventory sort mapping', () => {
  it('maps the URL sort field to the table column and back', () => {
    expect(sortToSorting('-risk_score')).toEqual([{ id: 'risk', desc: true }])
    expect(sortToSorting('finding_count')).toEqual([{ id: 'findings', desc: false }])
    expect(sortingToSort([{ id: 'risk', desc: true }])).toBe('-risk_score')
    expect(sortingToSort([{ id: 'name', desc: false }])).toBe('name')
  })

  it('ignores fields and columns the API cannot sort', () => {
    expect(sortToSorting('owner')).toEqual([])
    expect(sortToSorting(undefined)).toEqual([])
    expect(sortingToSort([{ id: 'owner', desc: false }])).toBeUndefined()
    expect(sortingToSort([])).toBeUndefined()
  })

  it('hides names awaiting review and rejected names unless attribution is chosen', () => {
    // No selection: the API gets the approved alias (confirmed, no record,
    // dependency, monitor only).
    expect(attributionQuery({})).toEqual(['approved'])
    const f = parseInventoryFilters(new URLSearchParams('attribution=needs_review,candidate'))
    expect(f.attribution).toEqual(['needs_review', 'candidate'])
    expect(attributionQuery(f)).toEqual(['needs_review', 'candidate'])
    expect(serializeInventoryFilters(f).get('attribution')).toBe('needs_review,candidate')
    expect(countActiveFilters(f)).toBe(2)
    expect(isInventoryFilterEmpty(f)).toBe(false)
  })
})

describe('typed inventory filters', () => {
  it('round-trips the sub-type and attribute filters with the API names', () => {
    const f: InventoryFilters = {
      types: ['identity'],
      subType: 'iam_user',
      propertiesFilter: { has_mfa: ['false'], provider: ['aws', 'gcp'] },
    }
    const qs = serializeInventoryFilters(f)
    expect(qs.get('sub_type')).toBe('iam_user')
    expect(qs.get('properties')).toBe('has_mfa:false,provider:aws,provider:gcp')
    expect(parseInventoryFilters(qs)).toEqual(f)
    expect(countActiveFilters(f)).toBe(5)
    expect(isInventoryFilterEmpty({ subType: 'iam_user' })).toBe(false)
  })

  it('drops attribute filters on keys outside the schema', () => {
    const f = parseInventoryFilters(new URLSearchParams('properties=os:linux,os_name:Ubuntu,bad'))
    expect(f.propertiesFilter).toEqual({ os_name: ['Ubuntu'] })
  })

  it('toggles one attribute value and resets the page', () => {
    const on = togglePropertyFilter({ page: 3 }, 'is_virtual', 'true')
    expect(on).toEqual({ page: 1, propertiesFilter: { is_virtual: ['true'] } })
    expect(togglePropertyFilter(on, 'is_virtual', 'true').propertiesFilter).toBeUndefined()
  })
})
