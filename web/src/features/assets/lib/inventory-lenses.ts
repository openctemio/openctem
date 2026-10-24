/**
 * Lens and type counts for the inventory's lens bar, from the data-scoped
 * asset stats (`by_type_sub_type`, keyed "type" or "type/sub_type") and the
 * type registry. Every row lands in exactly one place: its registry type's
 * lens, or "Other" when its class has no lens (unclassified assets).
 *
 * A chip is a stored type of the lens ("Subdomain", "Service"). An alias gets
 * its own chip only when it sits in another lens than its stored type (a
 * container registry is stored as storage but belongs to Containers), so the
 * chips never count a row twice.
 */
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'
import { ASSET_LENSES, type AssetLens } from '@/features/asset-types/registry.generated'

export interface LensTypeChip {
  /** The value written to `?types=`. */
  type: string
  label: string
  count: number
}

export interface LensCounts {
  /** Assets per lens (only lenses with at least one). */
  byLens: Partial<Record<AssetLens, number>>
  /** Type chips per lens, most assets first. */
  chips: Partial<Record<AssetLens, LensTypeChip[]>>
  /** Assets whose class has no lens. */
  other: number
  /** The `?types=` values that select the "Other" assets. */
  otherTypes: string[]
}

type TypeDef = NonNullable<AssetTypeRegistry['types']>[number]

const KNOWN_LENSES = new Set<string>(ASSET_LENSES.map((l) => l.id))

function place(
  types: TypeDef[],
  stored: string,
  sub: string | undefined
): { lens: AssetLens | null; type: string; label: string } {
  const core = types.find((t) => t.type === stored && !t.alias_of)
  const coreLens = (core?.lens as AssetLens | undefined) ?? null
  if (sub) {
    const alias = types.find((t) => t.alias_of?.type === stored && t.alias_of?.sub_type === sub)
    const aliasLens = (alias?.lens as AssetLens | undefined) ?? null
    if (alias && aliasLens !== coreLens) {
      return { lens: aliasLens, type: alias.type ?? stored, label: alias.label ?? stored }
    }
  }
  return { lens: coreLens, type: stored, label: core?.label ?? stored }
}

export function lensCounts(
  registry: AssetTypeRegistry | undefined,
  byTypeSubType: Record<string, number> | undefined
): LensCounts {
  const types = registry?.types ?? []
  const out: LensCounts = { byLens: {}, chips: {}, other: 0, otherTypes: [] }
  const chipMaps: Partial<Record<AssetLens, Map<string, LensTypeChip>>> = {}

  for (const [key, n] of Object.entries(byTypeSubType ?? {})) {
    if (!n) continue
    const [stored, sub] = key.split('/', 2)
    const p = place(types, stored, sub)
    if (!p.lens || !KNOWN_LENSES.has(p.lens)) {
      out.other += n
      if (!out.otherTypes.includes(p.type)) out.otherTypes.push(p.type)
      continue
    }
    out.byLens[p.lens] = (out.byLens[p.lens] ?? 0) + n
    const m = (chipMaps[p.lens] ??= new Map())
    const chip = m.get(p.type) ?? { type: p.type, label: p.label, count: 0 }
    chip.count += n
    m.set(p.type, chip)
  }
  for (const [lens, m] of Object.entries(chipMaps) as [AssetLens, Map<string, LensTypeChip>][]) {
    out.chips[lens] = [...m.values()].sort(
      (a, b) => b.count - a.count || a.label.localeCompare(b.label)
    )
  }
  out.otherTypes.sort()
  return out
}

/** The registry's lenses in order (the generated list until it has loaded). */
export function inventoryLenses(
  registry: AssetTypeRegistry | undefined
): { id: AssetLens; label: string; description?: string }[] {
  const served = (registry?.lenses ?? [])
    .filter((l): l is typeof l & { id: AssetLens } => KNOWN_LENSES.has(l.id ?? ''))
    .map((l) => ({ id: l.id, label: l.label ?? l.id, description: l.description }))
  return served.length > 0 ? served : ASSET_LENSES.map((l) => ({ id: l.id, label: l.label }))
}

/** One built-in view of the inventory: a lens (or all assets, or "Other") with its count. */
export interface AssetQuickView {
  /** `all`, a lens id, or `other`. */
  key: string
  /** English label; the i18n key is `assets.lens.<key>` (`assets.quickView.all` for all). */
  label: string
  /** The list URL, with the list's own params (`?lens=` or `?types=`). */
  href: string
  count: number
}

/**
 * The quick views listed under Assets in the sidebar: All assets, every lens
 * that holds at least one asset, then "Other" for assets outside every lens.
 * The counts are the caller's data-scoped stats (the same response the list
 * page reads), so a count and the list it opens always agree.
 */
export function assetQuickViews(
  registry: AssetTypeRegistry | undefined,
  total: number,
  counts: LensCounts
): AssetQuickView[] {
  const views: AssetQuickView[] = [
    { key: 'all', label: 'All assets', href: '/assets', count: total },
  ]
  for (const l of inventoryLenses(registry)) {
    const n = counts.byLens[l.id] ?? 0
    if (n > 0) views.push({ key: l.id, label: l.label, href: `/assets?lens=${l.id}`, count: n })
  }
  if (counts.other > 0) {
    const types = encodeURIComponent(counts.otherTypes.join(','))
    views.push({
      key: 'other',
      label: 'Other',
      href: `/assets?types=${types}`,
      count: counts.other,
    })
  }
  return views
}

/**
 * Which quick view the list URL shows: a lens, all assets (no lens and no
 * type), "Other" (exactly the types outside every lens), or none (a type
 * picked by hand, which is a filter, not a view).
 */
export function activeQuickView(search: URLSearchParams, counts: LensCounts): string | undefined {
  const lens = search.get('lens')
  if (lens) return KNOWN_LENSES.has(lens) ? lens : undefined
  const types = (search.get('types') ?? '').split(',').filter(Boolean)
  if (types.length === 0) return 'all'
  const other = new Set(counts.otherTypes)
  if (types.length === other.size && types.every((t) => other.has(t))) return 'other'
  return undefined
}

/**
 * The registry's name for a row's type: the alias for its sub-type when one
 * exists ("HTTP Service" for service/http), else the core type's label. `type`
 * is the i18n key segment (`assets.typeLabel.<type>`).
 */
export function typeKeyOf(
  registry: AssetTypeRegistry | undefined,
  stored: string,
  sub?: string | null
): { type: string; label: string } {
  const types = registry?.types ?? []
  if (sub) {
    const alias = types.find((t) => t.alias_of?.type === stored && t.alias_of?.sub_type === sub)
    if (alias?.type) return { type: alias.type, label: alias.label ?? alias.type }
  }
  const core = types.find((t) => t.type === stored && !t.alias_of)
  const fallback = stored.replace(/_/g, ' ')
  return {
    type: stored,
    label: core?.label ?? fallback.charAt(0).toUpperCase() + fallback.slice(1),
  }
}
