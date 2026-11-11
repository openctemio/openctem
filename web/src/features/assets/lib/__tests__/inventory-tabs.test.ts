import { describe, expect, it } from 'vitest'
import {
  INVENTORY_TABS,
  openTab,
  tabById,
  tabCounts,
  tabFromTypes,
  withTab,
} from '../inventory-tabs'
import { parseInventoryFilters, serializeInventoryFilters } from '../inventory-url'

const q = (s: string) => new URLSearchParams(s)

describe('the type tabs of the External surface lens', () => {
  it('lists the six types of the lens, each once', () => {
    expect(INVENTORY_TABS.map((t) => t.id)).toEqual([
      'domain',
      'subdomain',
      'ip_address',
      'service',
      'web_endpoint',
      'certificate',
    ])
  })

  it('?tab= selects one inside the lens only', () => {
    expect(parseInventoryFilters(q('lens=external_surface&tab=ip_address')).tab).toBe('ip_address')
    // Another lens keeps the type facet: a tab there means nothing.
    expect(parseInventoryFilters(q('lens=cloud_infra&tab=ip_address')).tab).toBeUndefined()
    expect(parseInventoryFilters(q('tab=ip_address')).tab).toBeUndefined()
    expect(parseInventoryFilters(q('lens=external_surface&tab=nonsense')).tab).toBeUndefined()
  })

  it('an old single-type link opens the matching tab', () => {
    const f = parseInventoryFilters(q('lens=external_surface&types=subdomain'))
    expect(f.tab).toBe('subdomain')
    expect(f.types).toBeUndefined()
    expect(tabFromTypes(['service'], 'discovered_url')?.id).toBe('web_endpoint')
    expect(tabFromTypes(['discovered_url'], undefined)?.id).toBe('web_endpoint')
    expect(tabFromTypes(['service'], undefined)?.id).toBe('service')
    // Several types, or a type with no tab, stay a type filter.
    expect(
      parseInventoryFilters(q('lens=external_surface&types=domain,subdomain')).tab
    ).toBeUndefined()
    expect(parseInventoryFilters(q('lens=external_surface&types=host')).types).toEqual(['host'])
  })

  it('writes the tab, not the type, and round-trips', () => {
    const f = parseInventoryFilters(q('lens=external_surface&types=ip_address&criticalities=high'))
    const out = serializeInventoryFilters(f)
    expect(out.get('tab')).toBe('ip_address')
    expect(out.get('types')).toBeNull()
    expect(parseInventoryFilters(out)).toEqual(f)
  })

  it('locks the type: the list runs with it, the viewer own filter does not hold it', () => {
    const f = parseInventoryFilters(q('lens=external_surface&tab=web_endpoint'))
    expect(f.types).toBeUndefined()
    const run = withTab(f)
    expect(run.types).toEqual(['service'])
    expect(run.subType).toBe('discovered_url')
    const services = withTab(parseInventoryFilters(q('lens=external_surface&tab=service')))
    expect(services.extra).toEqual({ sub_type_not: 'discovered_url' })
    expect(openTab(parseInventoryFilters(q('lens=data&tab=domain')))).toBeUndefined()
    expect(tabById('domain')?.type).toBe('domain')
  })

  it('counts each tab from its own stored rows', () => {
    const counts = tabCounts({
      domain: 3,
      subdomain: 40,
      ip_address: 12,
      'service/http': 5,
      'service/open_port': 7,
      'service/discovered_url': 9,
      service: 1,
      certificate: 2,
      host: 99,
    })
    expect(counts).toEqual({
      domain: 3,
      subdomain: 40,
      ip_address: 12,
      service: 13,
      web_endpoint: 9,
      certificate: 2,
    })
  })
})
