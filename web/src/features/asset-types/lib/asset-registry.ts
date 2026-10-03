/**
 * Class and lens lookups over the asset type registry (RFC-042 §6.3).
 *
 * The registry comes from GET /api/v1/asset-types. Until it has loaded (or if
 * the request fails) the generated constants in `registry.generated.ts`, which
 * come from the same YAML, answer instead, so a label never flashes empty.
 */
import type { AssetTypeRegistryResponse } from '@/lib/api/generated'
import {
  ASSET_ALIAS_CLASSES,
  ASSET_CLASSES,
  ASSET_LENSES,
  ASSET_TYPE_CLASSES,
  type AssetClass,
  type AssetLens,
} from '../registry.generated'

export type AssetTypeRegistry = AssetTypeRegistryResponse

const OTHER: AssetClass = 'other'

/**
 * The class of a stored asset. An alias keeps its own class: a `host` with
 * sub_type `serverless` is a `function` (same rule as the API's ClassOf and
 * the assets trigger).
 */
export function classOfAsset(
  registry: AssetTypeRegistry | undefined,
  type: string,
  subType?: string | null
): AssetClass {
  if (registry?.types?.length) {
    if (subType) {
      const alias = registry.types.find(
        (t) => t.alias_of?.type === type && t.alias_of?.sub_type === subType
      )
      if (alias?.class) return alias.class
    }
    return registry.types.find((t) => t.type === type)?.class ?? OTHER
  }
  if (subType) {
    const alias = ASSET_ALIAS_CLASSES[`${type}/${subType}`]
    if (alias) return alias
  }
  return (ASSET_TYPE_CLASSES as Record<string, AssetClass>)[type] ?? OTHER
}

/** The lens a class belongs to, or null for `other` (All assets only). */
export function lensOfClass(
  registry: AssetTypeRegistry | undefined,
  assetClass: AssetClass
): AssetLens | null {
  const served = registry?.classes?.find((c) => c.id === assetClass)
  if (served) return served.lens ?? null
  return ASSET_CLASSES.find((c) => c.id === assetClass)?.lens ?? null
}

export function classLabel(
  registry: AssetTypeRegistry | undefined,
  assetClass: AssetClass
): string {
  return (
    registry?.classes?.find((c) => c.id === assetClass)?.label ??
    ASSET_CLASSES.find((c) => c.id === assetClass)?.label ??
    assetClass
  )
}

export function lensLabel(registry: AssetTypeRegistry | undefined, lens: AssetLens): string {
  return (
    registry?.lenses?.find((l) => l.id === lens)?.label ??
    ASSET_LENSES.find((l) => l.id === lens)?.label ??
    lens
  )
}

/** "Code repository · Code"; just the class label for `other`. */
export function classAndLensLabel(
  registry: AssetTypeRegistry | undefined,
  type: string,
  subType?: string | null
): string {
  const assetClass = classOfAsset(registry, type, subType)
  const lens = lensOfClass(registry, assetClass)
  const label = classLabel(registry, assetClass)
  return lens ? `${label} · ${lensLabel(registry, lens)}` : label
}
