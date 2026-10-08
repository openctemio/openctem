/**
 * What the inventory shows for one asset type (research/77, RFC-042 §6.19):
 * its label, its attributes with their kind, the row columns, the facets and
 * whether scanners can scan it, all from the type registry
 * (GET /api/v1/asset-types). A new type is a registry entry; it needs no page.
 */
import type { AssetTypeDefinition } from '@/lib/api/generated'
import type { AssetTypeRegistry } from './asset-registry'
import { isPropertyKey, type AssetPropertyKey } from './property-schema'

export type AttributeKind =
  'string' | 'int' | 'number' | 'bool' | 'time' | 'enum' | 'list' | 'object'

export interface TypeAttribute {
  key: AssetPropertyKey
  kind: AttributeKind
  /** The closed values of an enum attribute. */
  values?: string[]
  facet: boolean
}

export interface TypeView {
  /** The stored type (`asset_type`). */
  type: string
  /** The stored sub-type the view is narrowed to, when an alias names one. */
  subType?: string
  label: string
  plural: string
  /** The type's attributes (an alias's first), each once. */
  attributes: TypeAttribute[]
  /** The row columns that are attributes (core columns are always shown). */
  columns: TypeAttribute[]
  /** Attributes a list can filter by: enum, bool, string and int facets. */
  facets: TypeAttribute[]
  /** Scanners can scan the type (registry `scannable_by`). */
  scannable: boolean
}

/**
 * A type label inside a sentence ("Add cloud account", "Add IAM user"):
 * words in capitals (acronyms) stay, the rest is lower case.
 */
export function inSentence(label: string): string {
  return label
    .split(' ')
    .map((w) => (w.length > 1 && w === w.toUpperCase() ? w : w.toLowerCase()))
    .join(' ')
}

const FACET_KINDS: ReadonlySet<AttributeKind> = new Set(['enum', 'bool', 'string', 'int'])

/** At most this many attribute facets are counted (the stats `count_by` cap). */
export const MAX_TYPE_FACETS = 10

function attributesOf(def: AssetTypeDefinition | undefined): TypeAttribute[] {
  const out: TypeAttribute[] = []
  for (const a of def?.attributes ?? []) {
    if (!a.name || !isPropertyKey(a.name)) continue
    out.push({
      key: a.name,
      kind: (a.type ?? 'string') as AttributeKind,
      values: a.values?.length ? a.values : undefined,
      facet: !!a.facet,
    })
  }
  return out
}

/**
 * The view for an inventory filtered to exactly one type (and optionally one
 * sub-type), or null for a mixed list. An alias (identity / iam_user) gives
 * its own label, attributes and columns; the core type's attributes follow.
 */
export function typeViewOf(
  registry: AssetTypeRegistry | undefined,
  types: readonly string[] | undefined,
  subType?: string
): TypeView | null {
  if (!registry?.types?.length || types?.length !== 1) return null
  const type = types[0]
  const core = registry.types.find((t) => t.type === type && !t.alias_of)
  if (!core) return null
  const alias = subType
    ? registry.types.find((t) => t.alias_of?.type === type && t.alias_of?.sub_type === subType)
    : undefined
  const def = alias ?? core

  const attributes: TypeAttribute[] = []
  for (const a of [...attributesOf(alias), ...attributesOf(core)]) {
    if (!attributes.some((x) => x.key === a.key)) attributes.push(a)
  }
  const byKey = new Map(attributes.map((a) => [a.key as string, a]))
  const columns = (def.columns ?? [])
    .map((c) => byKey.get(c))
    .filter((a): a is TypeAttribute => !!a)

  return {
    type,
    subType: subType || undefined,
    label: def.label ?? type,
    plural: def.plural ?? def.label ?? type,
    attributes,
    columns,
    facets: attributes.filter((a) => a.facet && FACET_KINDS.has(a.kind)).slice(0, MAX_TYPE_FACETS),
    // An alias without its own list inherits the core type's.
    scannable: (def.scannable_by?.length ? def.scannable_by : (core.scannable_by ?? [])).length > 0,
  }
}
