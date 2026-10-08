/**
 * The asset property schema (RFC-042 §6.3.9), from the generated registry.
 *
 * Every property key is declared once in api/configs/asset-types.yaml with
 * its labels, display format and synonyms; a type's schema is its own
 * attribute keys (and those of the alias its sub-type came from) plus the
 * common keys. The API folds synonyms on write; rows written before that
 * still hold them, so readers here fold too, and never keep a key list of
 * their own.
 */
import {
  ASSET_COMMON_PROPERTIES,
  ASSET_PROPERTIES,
  ASSET_TYPE_ALIASES,
  ASSET_TYPE_PROPERTIES,
  type AssetPropertyDefinition,
  type AssetPropertyFormat,
  type AssetPropertyKey,
} from '../registry.generated'

export type { AssetPropertyKey }

/** The canonical key of an asset's IP addresses. */
export const IP_ADDRESSES_KEY: AssetPropertyKey = 'ip_addresses'

/** True when `key` is a property key of the schema (not a synonym, not custom). */
export function isPropertyKey(key: string): key is AssetPropertyKey {
  return Object.prototype.hasOwnProperty.call(ASSET_PROPERTIES, key)
}

/**
 * The value an asset holds for a schema key. Web code reads a property only
 * through a typed key (this, or `propertyStrings` for list keys), so a key
 * outside the registry does not compile (docs/architecture/asset-inventory-v2.md,
 * "Property names").
 */
export function propertyValue(
  properties: Record<string, unknown> | undefined | null,
  key: AssetPropertyKey
): unknown {
  return properties?.[key]
}

const SYNONYM_OF: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(ASSET_PROPERTIES).flatMap(([key, def]) =>
    (def.synonyms ?? []).map((s) => [s, key] as const)
  )
)

/** The canonical key a synonym folds into, or the key itself. */
export function canonicalPropertyKey(key: string): string {
  return SYNONYM_OF[key] ?? key
}

/** The schema entry of a canonical key. */
export function propertyDefinition(key: string): AssetPropertyDefinition | undefined {
  return isPropertyKey(key) ? ASSET_PROPERTIES[key] : undefined
}

/** Humanized fallback label for a key outside the schema. */
export function humanizePropertyKey(key: string): string {
  const words = key.replace(/[-_]+/g, ' ').trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

/** The label of a key in the viewer's language (English when there is none). */
export function propertyLabel(key: string, locale?: string): string {
  const def = propertyDefinition(key)
  if (!def) return humanizePropertyKey(key)
  return locale?.startsWith('vi') && def.labelVi ? def.labelVi : def.label
}

/** The keys a stored (type, sub-type) has in its schema, in display order. */
export function propertyKeysOf(type: string, subType?: string | null): string[] {
  const out: string[] = []
  const add = (keys: readonly string[] | undefined) => {
    for (const k of keys ?? []) if (!out.includes(k)) out.push(k)
  }
  if (subType) {
    for (const [alias, to] of Object.entries(ASSET_TYPE_ALIASES)) {
      if (to.type === type && to.subType === subType) {
        add((ASSET_TYPE_PROPERTIES as Record<string, readonly string[]>)[alias])
      }
    }
  }
  add((ASSET_TYPE_PROPERTIES as Record<string, readonly string[]>)[type])
  add(ASSET_COMMON_PROPERTIES)
  return out
}

function isIP(s: string): boolean {
  // IPv4 dotted quad or an IPv6 literal (hex groups and colons).
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(s)) return s.split('.').every((p) => Number(p) <= 255)
  return /^[0-9a-f:.]+$/i.test(s) && s.includes(':')
}

function splitValue(s: string, format?: AssetPropertyFormat): string[] {
  if (format !== 'ip') {
    const t = s.trim()
    return t ? [t] : []
  }
  return s
    .split(/[,; ]+/)
    .map((p) => p.trim().toLowerCase())
    .filter(isIP)
}

function collect(value: unknown, format: AssetPropertyFormat | undefined, out: string[]) {
  const push = (s: string) => {
    for (const v of splitValue(s, format)) if (!out.includes(v)) out.push(v)
  }
  if (typeof value === 'string') push(value)
  else if (Array.isArray(value)) {
    for (const e of value) if (typeof e === 'string') push(e)
  } else if (format === 'ip' && value && typeof value === 'object') {
    const address = (value as Record<string, unknown>).address
    if (typeof address === 'string') push(address)
  }
}

/**
 * The string values an asset holds for a canonical key, from the key and any
 * synonym an older row still holds, without duplicates.
 */
export function propertyStrings(
  properties: Record<string, unknown> | undefined | null,
  key: string
): string[] {
  if (!properties) return []
  const def = propertyDefinition(key)
  const out: string[] = []
  collect(properties[key], def?.format, out)
  for (const s of def?.synonyms ?? []) collect(properties[s], def?.format, out)
  return out
}

export interface PropertyEntry {
  key: string
  value: unknown
  format?: AssetPropertyFormat
}

export interface GroupedProperties {
  /** Keys of the type's schema, in schema order, synonyms folded in. */
  known: PropertyEntry[]
  /** Keys outside the schema (third-party or custom), sorted. */
  other: PropertyEntry[]
}

/** Platform keys shown elsewhere in the detail view, never as a property. */
const HIDDEN = new Set(['aliases', 'identity_hints', 'x_native_sub_type'])

/**
 * Splits an asset's properties into the type's schema (labelled, in schema
 * order) and the rest. A synonym an older row still holds is shown under its
 * canonical key; an object under a synonym name (the CTIS technical
 * ip_address block) stays a key of its own.
 */
export function groupProperties(
  properties: Record<string, unknown> | undefined | null,
  type: string,
  subType?: string | null
): GroupedProperties {
  const props = properties ?? {}
  const schema = propertyKeysOf(type, subType)
  const used = new Set<string>()
  const known: PropertyEntry[] = []
  for (const key of schema) {
    if (HIDDEN.has(key)) continue
    const def = propertyDefinition(key)
    if (def?.synonyms?.length) {
      const values = propertyStrings(props, key)
      used.add(key)
      for (const s of def.synonyms) {
        const v = props[s]
        if (v !== undefined && !(v && typeof v === 'object' && !Array.isArray(v))) used.add(s)
      }
      if (values.length > 0) known.push({ key, value: values, format: def.format })
      continue
    }
    if (props[key] === undefined) continue
    used.add(key)
    known.push({ key, value: props[key], format: def?.format })
  }
  // A canonical key with synonyms (ip_addresses) that is not in this type's
  // schema still folds: its values are shown once, labelled.
  for (const [key, def] of Object.entries(ASSET_PROPERTIES)) {
    if (!def.synonyms?.length || used.has(key)) continue
    const values = propertyStrings(props, key)
    const present = [key, ...def.synonyms].filter(
      (k) =>
        props[k] !== undefined &&
        !(props[k] && typeof props[k] === 'object' && !Array.isArray(props[k]))
    )
    if (present.length === 0) continue
    present.forEach((k) => used.add(k))
    if (values.length > 0) known.push({ key, value: values, format: def.format })
  }
  const other = Object.keys(props)
    .filter((k) => !used.has(k) && !HIDDEN.has(k) && !schema.includes(k))
    .sort()
    .map((key) => ({ key, value: props[key], format: propertyDefinition(key)?.format }))
  return { known, other }
}
