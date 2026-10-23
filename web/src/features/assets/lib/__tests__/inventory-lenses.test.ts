/**
 * The inventory lenses: every row counted once in its lens (aliases in their
 * own lens only when it differs), and the sidebar's quick views built from
 * the caller's own (scoped) stats, with the view the URL shows.
 */
import { describe, it, expect } from 'vitest'
import { activeQuickView, assetQuickViews, lensCounts } from '../inventory-lenses'
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'

const REGISTRY = {
  lenses: [
    { id: 'external_surface', label: 'External surface' },
    { id: 'applications', label: 'Applications' },
    { id: 'containers_k8s', label: 'Containers & Kubernetes' },
    { id: 'data', label: 'Data' },
    { id: 'identities', label: 'Identities' },
  ],
  types: [
    { type: 'subdomain', label: 'Subdomain', lens: 'external_surface' },
    { type: 'service', label: 'Service', lens: 'external_surface' },
    {
      type: 'http_service',
      label: 'HTTP Service',
      lens: 'external_surface',
      alias_of: { type: 'service', sub_type: 'http' },
    },
    { type: 'ip_address', label: 'IP Address', lens: 'external_surface' },
    { type: 'application', label: 'Application', lens: 'applications' },
    { type: 'storage', label: 'Storage', lens: 'data' },
    { type: 'container', label: 'Container', lens: 'containers_k8s' },
    {
      type: 'container_registry',
      label: 'Container Registry',
      lens: 'containers_k8s',
      alias_of: { type: 'storage', sub_type: 'container_registry' },
    },
    { type: 'unclassified', label: 'Unclassified', class: 'other' },
  ],
} as unknown as AssetTypeRegistry

// What a scoped member's /assets/stats returns: only their assets.
const SCOPED = {
  subdomain: 105,
  service: 60,
  'service/http': 42,
  ip_address: 70,
  application: 4,
  'storage/bucket': 3,
  'storage/container_registry': 2,
  unclassified: 1,
}

describe('lensCounts', () => {
  it('places every row once: aliases in their own lens only when it differs', () => {
    const c = lensCounts(REGISTRY, SCOPED)
    expect(c.byLens).toEqual({ external_surface: 277, applications: 4, data: 3, containers_k8s: 2 })
    // http_service rows count under Service (same lens), the registry under Containers.
    expect(c.chips.external_surface?.map((x) => [x.type, x.count])).toEqual([
      ['subdomain', 105],
      ['service', 102],
      ['ip_address', 70],
    ])
    expect(c.chips.containers_k8s).toEqual([
      { type: 'container_registry', label: 'Container Registry', count: 2 },
    ])
    expect(c.other).toBe(1)
    expect(c.otherTypes).toEqual(['unclassified'])
  })
})

describe('assetQuickViews', () => {
  const counts = lensCounts(REGISTRY, SCOPED)

  it('lists All assets, every lens with an asset in registry order, then Other', () => {
    const views = assetQuickViews(REGISTRY, 287, counts)
    expect(views.map((v) => [v.key, v.count, v.href])).toEqual([
      ['all', 287, '/assets'],
      ['external_surface', 277, '/assets?lens=external_surface'],
      ['applications', 4, '/assets?lens=applications'],
      ['containers_k8s', 2, '/assets?lens=containers_k8s'],
      ['data', 3, '/assets?lens=data'],
      ['other', 1, '/assets?types=unclassified'],
    ])
  })

  it('data scope: a lens whose assets are all outside the caller’s scope is not listed', () => {
    const scoped = lensCounts(REGISTRY, { application: 4 })
    const keys = assetQuickViews(REGISTRY, 4, scoped).map((v) => v.key)
    expect(keys).toEqual(['all', 'applications'])
  })

  it('names the view the URL shows', () => {
    const q = (s: string) => new URLSearchParams(s)
    expect(activeQuickView(q(''), counts)).toBe('all')
    expect(activeQuickView(q('criticalities=high'), counts)).toBe('all')
    expect(activeQuickView(q('lens=data'), counts)).toBe('data')
    expect(activeQuickView(q('lens=data&types=storage'), counts)).toBe('data')
    expect(activeQuickView(q('types=unclassified'), counts)).toBe('other')
    // A type picked by hand is a filter, not a view; an unknown lens is no view.
    expect(activeQuickView(q('types=subdomain'), counts)).toBeUndefined()
    expect(activeQuickView(q('lens=bogus'), counts)).toBeUndefined()
  })
})
