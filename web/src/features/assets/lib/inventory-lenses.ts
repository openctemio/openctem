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

/** The lens a single selected type belongs to (typed mode keeps its lens pill lit). */
export function lensOfType(
  registry: AssetTypeRegistry | undefined,
  type: string | undefined
): AssetLens | undefined {
  if (!type) return undefined
  const def = registry?.types?.find((t) => t.type === type)
  const lens = def?.lens as AssetLens | undefined
  return lens && KNOWN_LENSES.has(lens) ? lens : undefined
}
