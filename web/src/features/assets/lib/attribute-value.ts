/**
 * The value of a type attribute on an asset, for list cells, CSV export and
 * the attribute facets (research/77). One function, so the inventory never
 * keeps a per-type key list.
 *
 * An attribute is a flat property key (api/configs/asset-types.yaml). Two
 * types keep some facts in a column or an extension table instead of
 * `properties`; the registry declares them as attributes all the same:
 *  - `provider` is the assets.provider column on every type;
 *  - a repository's `visibility`, `language`, `default_branch`,
 *    `canonical_url` (web URL) and `archived` come from its extension, which
 *    the list endpoint joins when it lists repositories.
 */
import {
  propertyStrings,
  propertyValue,
  type AssetPropertyKey,
} from '@/features/asset-types/lib/property-schema'
import type { Asset } from '../types'

type ExtensionKey = 'visibility' | 'language' | 'default_branch' | 'canonical_url'

const REPOSITORY_FIELDS: Record<ExtensionKey, (a: Asset) => unknown> = {
  visibility: (a) => a.repository?.visibility,
  language: (a) => a.repository?.language,
  default_branch: (a) => a.repository?.defaultBranch,
  canonical_url: (a) => a.repository?.webUrl,
}

function present(v: unknown): boolean {
  if (v === undefined || v === null) return false
  if (typeof v === 'string') return v.trim() !== ''
  if (Array.isArray(v)) return v.length > 0
  return true
}

/** The raw value of an attribute, or undefined when the asset does not carry it. */
export function attributeValue(asset: Asset, key: AssetPropertyKey): unknown {
  const v = propertyValue(asset.metadata, key)
  if (present(v)) return v
  if (key === 'provider' && present(asset.provider)) return asset.provider
  if (key in REPOSITORY_FIELDS) {
    const ext = REPOSITORY_FIELDS[key as ExtensionKey](asset)
    if (present(ext)) return ext
  }
  return undefined
}

/** The values of a list attribute as strings (synonyms folded for `ip_addresses`). */
export function attributeStrings(asset: Asset, key: AssetPropertyKey): string[] {
  const fromProps = propertyStrings(asset.metadata, key)
  if (fromProps.length > 0) return fromProps
  const v = attributeValue(asset, key)
  if (Array.isArray(v)) return v.map((x) => String(x)).filter((x) => x.trim() !== '')
  return present(v) ? [String(v)] : []
}

/** A value as one line of text (CSV export, titles). */
export function attributeText(asset: Asset, key: AssetPropertyKey): string {
  const v = attributeValue(asset, key)
  if (v === undefined) return ''
  if (Array.isArray(v)) return attributeStrings(asset, key).join('; ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}
