/**
 * Matching an asset against type names (RFC-042 §6.3.8).
 *
 * Only core types are stored: a web application is `application` with
 * sub-type `website`, a firewall is `network/firewall`. Feature lists still
 * speak in friendlier names (`website`, `k8s_cluster`, `api_endpoint`), so
 * every comparison resolves the name to the stored (type, sub-type) pair
 * through the generated registry instead of comparing strings. Comparing an
 * asset's type with an alias name silently never matches.
 */

import {
  ASSET_RELATIONSHIP_NAMES,
  ASSET_TYPE_ALIASES,
} from '@/features/asset-types/registry.generated'

/** An asset as type-aware features see it: its stored type and sub-type. */
export interface AssetTypeRef {
  type: string
  subType?: string
}

/**
 * The stored pair an asset stands for. A row still stored under a legacy
 * alias name (before the data normalisation) reads as its alias's pair.
 */
export function canonicalAssetType(ref: AssetTypeRef | string): AssetTypeRef {
  const r = typeof ref === 'string' ? { type: ref } : ref
  const alias = ASSET_TYPE_ALIASES[r.type]
  if (alias) return { type: alias.type, subType: r.subType || alias.subType }
  return { type: r.type, subType: r.subType || undefined }
}

/** The stored pair a type name stands for (a core name stands for itself). */
export function resolveTypeName(name: string): AssetTypeRef {
  return ASSET_RELATIONSHIP_NAMES[name] ?? ASSET_TYPE_ALIASES[name] ?? { type: name }
}

/**
 * Whether a type name covers an asset. A name without a sub-type covers every
 * asset of its type; an asset without a sub-type (its kind was never
 * recorded) is covered by every name of its type.
 */
export function assetMatchesTypeName(name: string, ref: AssetTypeRef | string): boolean {
  const asset = canonicalAssetType(ref)
  const want = resolveTypeName(name)
  if (want.type !== asset.type) return false
  return !want.subType || !asset.subType || want.subType === asset.subType
}

/** Whether any of the names covers the asset. */
export function assetMatchesAnyTypeName(
  names: readonly string[] | undefined,
  ref: AssetTypeRef | string
): boolean {
  return (names ?? []).some((n) => assetMatchesTypeName(n, ref))
}
