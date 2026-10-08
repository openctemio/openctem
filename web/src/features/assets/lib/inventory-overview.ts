/**
 * The inventory overview (research/77 §9): the overview counts
 * (GET /assets/overview) grouped by the registry's lenses, with a link for
 * every count into the filtered inventory. Nothing here names a type: a new
 * type or lens appears with no web change.
 */
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'
import type { InventoryOverviewRow } from '../api/use-inventory-overview'
import {
  HIGH_RISK_SCORE,
  serializeInventoryFilters,
  type AssetType,
  type InventoryFilters,
} from './inventory-url'
import { ASSET_LENSES } from '@/features/asset-types/registry.generated'

export interface OverviewTypeRow {
  key: string
  label: string
  count: number
  href: string
}

export interface OverviewLens {
  /** Registry lens id; '' for assets of class `other`. */
  id: string
  label: string
  description?: string
  total: number
  unowned: number
  highRisk: number
  new7d: number
  needsReview: number
  types: OverviewTypeRow[]
  /** The inventory with every type of the lens. */
  href: string
  unownedHref: string
  highRiskHref: string
  reviewHref: string
}

function href(f: InventoryFilters): string {
  const qs = serializeInventoryFilters(f).toString()
  return qs ? `/assets?${qs}` : '/assets'
}

/** The label of a stored (type, sub-type): its alias's plural, else its type's. */
function typeLabel(
  registry: AssetTypeRegistry | undefined,
  type: string,
  subType: string
): { key: string; label: string; subType?: string } {
  const defs = registry?.types ?? []
  if (subType) {
    const alias = defs.find((d) => d.alias_of?.type === type && d.alias_of?.sub_type === subType)
    if (alias)
      return { key: `${type}/${subType}`, label: alias.plural ?? alias.label ?? subType, subType }
  }
  const core = defs.find((d) => d.type === type && !d.alias_of)
  return { key: type, label: core?.plural ?? core?.label ?? type }
}

/** Every registry lens in order (empty ones too), then `other` when it has assets. */
export function buildOverview(
  registry: AssetTypeRegistry | undefined,
  rows: readonly InventoryOverviewRow[]
): OverviewLens[] {
  const lensDefs = (registry?.lenses ?? []).map((l) => ({
    id: l.id ?? '',
    label: l.label ?? l.id ?? '',
    description: l.description,
  }))
  const known = new Set(lensDefs.map((l) => l.id))
  const groups: { id: string; label: string; description?: string }[] = [...lensDefs]
  if (rows.some((r) => !known.has(r.lens))) groups.push({ id: '', label: 'Other' })

  return groups.map((g) => {
    const mine = rows.filter((r) => (known.has(r.lens) ? r.lens === g.id : g.id === ''))
    const byKey = new Map<string, OverviewTypeRow & { type: string; subType?: string }>()
    for (const r of mine) {
      const t = typeLabel(registry, r.type, r.sub_type)
      const row = byKey.get(t.key) ?? {
        key: t.key,
        label: t.label,
        count: 0,
        type: r.type,
        subType: t.subType,
        href: href({ types: [r.type as AssetType], subType: t.subType }),
      }
      row.count += r.total
      byKey.set(t.key, row)
    }
    const types = [...byKey.values()]
      .filter((t) => t.count > 0)
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
      .map(({ key, label, count, href: h }) => ({ key, label, count, href: h }))
    const allTypes = [...new Set(mine.map((r) => r.type))].sort()
    const sum = (f: (r: InventoryOverviewRow) => number) => mine.reduce((n, r) => n + f(r), 0)
    // A lens links by its id, so its aliases stored under another type's name
    // come along; `Other` (no lens) lists its types.
    const lensId = ASSET_LENSES.find((l) => l.id === g.id)?.id
    const lensFilter: InventoryFilters = lensId
      ? { lens: lensId }
      : allTypes.length > 0
        ? { types: allTypes as AssetType[] }
        : {}
    return {
      id: g.id,
      label: g.label,
      description: g.description,
      total: sum((r) => r.total),
      unowned: sum((r) => r.unowned),
      highRisk: sum((r) => r.high_risk),
      new7d: sum((r) => r.new_7d),
      needsReview: sum((r) => r.needs_review),
      types,
      href: href(lensFilter),
      unownedHref: href({ ...lensFilter, hasOwner: false }),
      highRiskHref: href({ ...lensFilter, minRiskScore: HIGH_RISK_SCORE, sort: '-risk_score' }),
      reviewHref: href({ ...lensFilter, attribution: ['needs_review', 'candidate'] }),
    }
  })
}
