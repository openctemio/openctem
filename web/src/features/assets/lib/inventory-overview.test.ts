import { describe, expect, it } from 'vitest'
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'
import type { InventoryOverviewRow } from '../api/use-inventory-overview'
import { buildOverview } from './inventory-overview'

const registry = {
  lenses: [
    { id: 'external_surface', label: 'External surface', description: 'Names and addresses.' },
    { id: 'identities', label: 'Identities' },
    { id: 'code', label: 'Code' },
  ],
  types: [
    { type: 'domain', label: 'Domain', plural: 'Domains' },
    { type: 'identity', label: 'Identity', plural: 'Identities' },
    {
      type: 'iam_user',
      label: 'IAM User',
      plural: 'IAM Users',
      alias_of: { type: 'identity', sub_type: 'iam_user' },
    },
  ],
} as unknown as AssetTypeRegistry

function row(over: Partial<InventoryOverviewRow>): InventoryOverviewRow {
  return {
    lens: '',
    type: '',
    sub_type: '',
    total: 0,
    unowned: 0,
    high_risk: 0,
    new_7d: 0,
    needs_review: 0,
    ...over,
  }
}

describe('buildOverview', () => {
  const rows = [
    row({
      lens: 'external_surface',
      type: 'domain',
      total: 4,
      unowned: 1,
      new_7d: 2,
      needs_review: 3,
    }),
    row({ lens: 'identities', type: 'identity', sub_type: 'iam_user', total: 5, high_risk: 1 }),
    row({ lens: 'identities', type: 'identity', total: 2 }),
    row({ lens: '', type: 'unclassified', total: 1 }),
  ]
  const lenses = buildOverview(registry, rows)

  it('has every registry lens in order, empty ones too, then Other', () => {
    expect(lenses.map((l) => l.label)).toEqual(['External surface', 'Identities', 'Code', 'Other'])
    expect(lenses[2].total).toBe(0)
    expect(lenses[3].types[0]).toMatchObject({ label: 'unclassified', count: 1 })
  })

  it('labels an alias sub-type with its own plural and links to the typed inventory', () => {
    const ids = lenses[1]
    expect(ids.total).toBe(7)
    expect(ids.types).toEqual([
      {
        key: 'identity/iam_user',
        label: 'IAM Users',
        count: 5,
        href: '/assets?types=identity&sub_type=iam_user',
      },
      { key: 'identity', label: 'Identities', count: 2, href: '/assets?types=identity' },
    ])
  })

  it('links each attention count to the lens of the inventory, filtered', () => {
    const ext = lenses[0]
    expect(ext).toMatchObject({ unowned: 1, new7d: 2, needsReview: 3 })
    expect(ext.href).toBe('/assets?lens=external_surface')
    expect(ext.unownedHref).toBe('/assets?has_owner=false&lens=external_surface')
    expect(ext.reviewHref).toBe(
      '/assets?attribution=needs_review%2Ccandidate&lens=external_surface'
    )
  })

  it('links high risk to the assets at or above the high-risk score, riskiest first', () => {
    expect(lenses[1].highRiskHref).toBe(
      '/assets?sort=-risk_score&lens=identities&min_risk_score=70'
    )
  })

  it('links Other, which has no lens, by its types', () => {
    expect(lenses[3].href).toBe('/assets?types=unclassified')
  })
})
