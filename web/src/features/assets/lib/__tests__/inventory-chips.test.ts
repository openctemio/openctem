/**
 * Inventory chips: every filter in the URL is one chip, read through the
 * facet registry, and removing a chip clears only that filter (back on page 1).
 */
import { describe, it, expect } from 'vitest'
import { inventoryChips, type ChipContext } from '../inventory-chips'
import { buildFacetGroups } from '../inventory-facets'
import { parseInventoryFilters } from '../inventory-url'

// A translator that fills {vars} into the English fallback, like the real one.
const t = (_key: string, fallback?: string, vars?: Record<string, string | number>) =>
  (fallback ?? '').replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))

const ctx = (): ChipContext => ({
  groups: buildFacetGroups({ 'bu-1': 'Retail' }, t, {
    labels: { subdomain: 'Subdomain', service: 'Service' },
    counts: { subdomain: 3, service: 2 },
  }),
  t,
  propertyLabel: (k) => (k === 'os_family' ? 'OS family' : k),
  formatDate: (iso) => iso.slice(0, 10),
})

const chipsOf = (qs: string) =>
  inventoryChips(parseInventoryFilters(new URLSearchParams(qs)), ctx())

describe('inventoryChips', () => {
  it('reads facets as sentences with their labels', () => {
    const texts = chipsOf(
      'types=subdomain,service&criticalities=critical,high&business_unit_ids=bu-1&internet_facing=true&has_owner=false'
    ).map((c) => c.text)
    expect(texts).toEqual([
      'Type is Subdomain, Service',
      'Criticality is Critical, High',
      'Business unit is Retail',
      'Unowned',
      'Internet-facing',
    ])
  })

  it('shows filters that are not facets too, so nothing narrows the list unseen', () => {
    const texts = chipsOf(
      'is_crown_jewel=true&has_findings=true&min_risk_score=70&coverage=uncovered&tags=prod,pci&exclude_tags=old&technology=nginx&properties=os_family:linux&first_seen_after=2026-10-01T00:00:00Z'
    ).map((c) => c.text)
    expect(texts).toEqual(
      expect.arrayContaining([
        'Crown jewels',
        'Has findings',
        'Risk score at least 70',
        'No successful scan in 30 days',
        'Tag is prod, pci',
        'Tag is not old',
        'Technology is nginx',
        'OS family is linux',
        'First seen after 2026-10-01',
      ])
    )
  })

  it('shortens long value lists and names the all-attribution view', () => {
    expect(chipsOf('criticalities=critical,high,medium,low')[0].text).toBe(
      'Criticality is Critical, High, Medium +1'
    )
    expect(chipsOf('attribution=all')[0].text).toBe(
      'Every name, including awaiting review and not ours'
    )
  })

  it('removing a chip clears only its filter and returns to page 1', () => {
    const f = parseInventoryFilters(
      new URLSearchParams('lens=external_surface&criticalities=high&tags=prod&tags_mode=all&page=3')
    )
    const chips = inventoryChips(f, ctx())
    const tags = chips.find((c) => c.key === 'tags')!
    expect(tags.text).toBe('Tags include all of prod')
    const next = tags.clear(f)
    expect(next.tags).toBeUndefined()
    expect(next.tagsMode).toBeUndefined()
    expect(next.criticalities).toEqual(['high'])
    expect(next.lens).toBe('external_surface')
    expect(next.page).toBe(1)
  })

  it('a date window is one chip, cleared as a whole', () => {
    const f = parseInventoryFilters(
      new URLSearchParams('expires_after=2026-10-01T00:00:00Z&expires_before=2026-10-31T00:00:00Z')
    )
    const chips = inventoryChips(f, ctx())
    expect(chips.map((c) => c.text)).toEqual(['Expires between 2026-10-01 and 2026-10-31'])
    const next = chips[0].clear(f)
    expect(next.expiresAfter).toBeUndefined()
    expect(next.expiresBefore).toBeUndefined()
  })

  it('the lens, search, sort and page are not chips', () => {
    expect(chipsOf('lens=code&q=api&sort=-risk_score&page=2')).toEqual([])
  })
})
