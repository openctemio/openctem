import { describe, expect, it } from 'vitest'
import { inventoryChips, type ChipContext } from '../inventory-chips'
import { applyPreset, deactivatePreset, tabPresets } from '../inventory-facets'
import { parseInventoryFilters, serializeInventoryFilters } from '../inventory-url'

const t = (_k: string, fb?: string, vars?: Record<string, string | number>) =>
  (fb ?? '').replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))
const ctx: ChipContext = { groups: [], t, propertyLabel: (k) => k, formatDate: (s) => s }
const q = (s: string) => new URLSearchParams(s)

describe('filters the page has no control for', () => {
  it('ride in the URL under the API names, and only the known ones', () => {
    const f = parseInventoryFilters(q('network=198.51.100.0/24&port_gte=1&bogus=1&page_x=2&q=a'))
    expect(f.extra).toEqual({ network: '198.51.100.0/24', port_gte: '1' })
    const out = serializeInventoryFilters(f)
    expect(out.get('network')).toBe('198.51.100.0/24')
    expect(out.get('bogus')).toBeNull()
    expect(parseInventoryFilters(out)).toEqual(f)
  })

  it('are one chip each, removable alone', () => {
    const f = parseInventoryFilters(q('network=198.51.100.0/24&port_gte=1&service_not=ssh'))
    const chips = inventoryChips(f, ctx)
    expect(chips.map((c) => c.text)).toEqual([
      'network is 198.51.100.0/24',
      'port at least 1',
      'service is not ssh',
    ])
    const left = chips[0].clear(f)
    expect(left.extra).toEqual({ port_gte: '1', service_not: 'ssh' })
    expect(chips[1].clear(chips[0].clear(chips[2].clear(f))).extra).toBeUndefined()
  })
})

describe('the starter views of the IP addresses tab', () => {
  it('are few: public addresses, with open ports, seen in the last 7 days', () => {
    expect(tabPresets('ip_address').map((p) => p.label)).toEqual([
      'Public addresses',
      'With open ports',
      'Seen in the last 7 days',
    ])
    expect(tabPresets('subdomain').map((p) => p.label)).toEqual(['Not resolving', 'New this week'])
    expect(tabPresets('certificate')).toEqual([])
  })

  it('turn on beside the viewer own extra filters and off without losing them', () => {
    const open = tabPresets('ip_address').find((p) => p.id === 'with-open-ports')!
    const on = applyPreset(parseInventoryFilters(q('network=198.51.100.0/24')), open)
    expect(on.extra).toEqual({ network: '198.51.100.0/24', port_gte: '1' })
    expect(open.isActive(on)).toBe(true)
    const off = deactivatePreset(on, open)
    expect(off.extra).toEqual({ network: '198.51.100.0/24' })
    expect(open.isActive(off)).toBe(false)
  })
})
