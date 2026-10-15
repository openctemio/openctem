/**
 * The form of a tool's settings on a sensor, generated from its settings
 * schema (`descriptor.config`, the closed JSON Schema subset of the CTIS
 * settings contract) as the API returns it from the sensor's current
 * manifest. The schema is a claim from the sensor: every field is checked for
 * its type here, unknown or malformed parts are skipped, and every string is
 * rendered as text. The API validates every save with the same contract the
 * sensor uses; the bounds here only help the person typing.
 *
 * Common options (`x-octm-common`: timeout, rate, concurrency, retries) mean
 * the same thing for every tool and come first; the tool's own options follow,
 * grouped by `x-octm-group` (or their object group).
 */

import { COMMON_OPTIONS, type CommonOption } from './tool-options'

export { COMMON_OPTIONS, type CommonOption }

/** Safety class of a non-default value (x-octm-tier). */
export type SettingTier = 'T0' | 'T1' | 'T2'

export type SettingKind = 'boolean' | 'integer' | 'number' | 'enum' | 'string' | 'multi' | 'list'

/** A scalar the schema can carry. */
export type SettingScalar = string | number | boolean

export interface ToolSettingField {
  /** The key ("rate_limit"), "group.key" for a key of an object group. */
  key: string
  kind: SettingKind
  common?: CommonOption
  /** The tool's native flag ("-rate-limit"), display only. */
  flag?: string
  title?: string
  description?: string
  defaultValue?: SettingScalar | SettingScalar[]
  minimum?: number
  maximum?: number
  /** Allowed values (enum, or an array's item enum). */
  values?: string[]
  scope: 'sensor' | 'scan'
  tier: SettingTier
  /** Display group (common options have none). */
  group?: string
  order: number
}

/** Bounds on what a hostile schema can make the page render. */
const MAX_FIELDS = 64
const MAX_TEXT = 500
const MAX_VALUES = 64

const FLAG_RE = /^--?[A-Za-z][A-Za-z0-9-]{0,47}$/
const TIERS = new Set(['T0', 'T1', 'T2'])

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function text(v: unknown): string | undefined {
  if (typeof v !== 'string' || v === '') return undefined
  return v.length > MAX_TEXT ? `${v.slice(0, MAX_TEXT)}…` : v
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

function scalar(v: unknown): SettingScalar | undefined {
  if (typeof v === 'string') return text(v) ?? ''
  if (typeof v === 'boolean') return v
  return num(v)
}

function scalarList(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined
  const out = v
    .slice(0, MAX_VALUES)
    .map(scalar)
    .filter((x): x is SettingScalar => x !== undefined && x !== '')
    .map(String)
  return out.length > 0 ? out : undefined
}

function kindOf(raw: Record<string, unknown>): SettingKind | undefined {
  const items = isObject(raw.items) ? raw.items : undefined
  switch (raw.type) {
    case 'boolean':
      return 'boolean'
    case 'integer':
      return 'integer'
    case 'number':
      return 'number'
    case 'string':
      return scalarList(raw.enum) ? 'enum' : 'string'
    case 'array':
      if (items && scalarList(items.enum)) return 'multi'
      return items?.type === 'string' ? 'list' : undefined
    default:
      return scalarList(raw.enum) ? 'enum' : undefined
  }
}

function readField(
  key: string,
  raw: Record<string, unknown>,
  group?: string
): ToolSettingField | undefined {
  // Sensitive and write-only keys are never plain values: the API refuses
  // them, so the form does not offer them.
  if (raw['x-octm-sensitive'] === true || raw.writeOnly === true) return undefined
  const kind = kindOf(raw)
  if (!kind) return undefined
  const items = isObject(raw.items) ? raw.items : undefined
  const common =
    typeof raw['x-octm-common'] === 'string' &&
    (COMMON_OPTIONS as readonly string[]).includes(raw['x-octm-common'])
      ? (raw['x-octm-common'] as CommonOption)
      : undefined
  const flag =
    typeof raw['x-octm-flag'] === 'string' && FLAG_RE.test(raw['x-octm-flag'])
      ? raw['x-octm-flag']
      : undefined
  const tier = typeof raw['x-octm-tier'] === 'string' && TIERS.has(raw['x-octm-tier'])
  const def = Array.isArray(raw.default)
    ? (raw.default
        .slice(0, MAX_VALUES)
        .map(scalar)
        .filter((x) => x !== undefined) as SettingScalar[])
    : scalar(raw.default)
  return {
    key,
    kind,
    common,
    flag,
    title: text(raw.title),
    description: text(raw.description),
    defaultValue: def,
    minimum: num(raw.minimum),
    maximum: num(raw.maximum),
    values: scalarList(raw.enum) ?? (items ? scalarList(items.enum) : undefined),
    scope: raw['x-octm-scope'] === 'scan' ? 'scan' : 'sensor',
    tier: tier ? (raw['x-octm-tier'] as SettingTier) : 'T0',
    group: common ? undefined : group,
    order: num(raw['x-octm-order']) ?? 0,
  }
}

function commonRank(f: ToolSettingField): number {
  return f.common ? COMMON_OPTIONS.indexOf(f.common) : COMMON_OPTIONS.length
}

/**
 * The fields of a settings schema: common options first (in COMMON_OPTIONS
 * order), then the tool's own by group, order and key. [] for anything that
 * is not a schema object.
 */
export function toolSettingFields(schema: unknown): ToolSettingField[] {
  if (!isObject(schema) || !isObject(schema.properties)) return []
  const out: ToolSettingField[] = []
  const push = (f: ToolSettingField | undefined) => {
    if (f && out.length < MAX_FIELDS) out.push(f)
  }
  for (const [key, raw] of Object.entries(schema.properties)) {
    if (!isObject(raw)) continue
    if (raw.type === 'object' && isObject(raw.properties)) {
      const group = text(raw.title) ?? key
      for (const [sub, subRaw] of Object.entries(raw.properties)) {
        if (isObject(subRaw)) push(readField(`${key}.${sub}`, subRaw, group))
      }
      continue
    }
    push(readField(key, raw, text(raw['x-octm-group'])))
  }
  return out.sort(
    (a, b) =>
      commonRank(a) - commonRank(b) ||
      (a.group ?? '').localeCompare(b.group ?? '') ||
      a.order - b.order ||
      a.key.localeCompare(b.key)
  )
}

/** One field's input as the form holds it; undefined: not set (default). */
export type DraftValue = string | boolean | string[] | undefined
export type Draft = Record<string, DraftValue>

function lookup(values: Record<string, unknown>, key: string): unknown {
  const [name, sub] = key.split('.', 2)
  const v = values[name]
  if (sub === undefined) return v
  return isObject(v) ? v[sub] : undefined
}

/** The form's draft for stored values. */
export function draftFromValues(
  fields: ToolSettingField[],
  values: Record<string, unknown> | undefined
): Draft {
  const draft: Draft = {}
  for (const f of fields) {
    const v = values ? lookup(values, f.key) : undefined
    if (v === undefined || v === null) continue
    if (f.kind === 'boolean') draft[f.key] = v === true
    else if (f.kind === 'multi' || f.kind === 'list')
      draft[f.key] = Array.isArray(v) ? v.map(String) : undefined
    else draft[f.key] = String(v)
  }
  return draft
}

/**
 * The values document for a draft: unset fields left out (they take their
 * default), numbers parsed, group keys nested. A number that does not parse
 * is sent as typed so the API names the field.
 */
export function valuesFromDraft(fields: ToolSettingField[], draft: Draft): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const f of fields) {
    const d = draft[f.key]
    if (d === undefined || d === '') continue
    let v: unknown = d
    if ((f.kind === 'integer' || f.kind === 'number') && typeof d === 'string') {
      const n = Number(d)
      v = d.trim() !== '' && Number.isFinite(n) ? n : d
    }
    if (f.kind === 'list' && Array.isArray(d) && d.length === 0) continue
    const [name, sub] = f.key.split('.', 2)
    if (sub === undefined) out[name] = v
    else out[name] = { ...(isObject(out[name]) ? out[name] : {}), [sub]: v }
  }
  return out
}

/** "/dns/retries" → "dns.retries"; "" stays "" (the whole document). */
export function problemKey(path: string): string {
  return path.replace(/^\//, '').split('/').join('.')
}

/** A default as placeholder text. */
export function defaultText(f: ToolSettingField): string {
  const d = f.defaultValue
  if (d === undefined) return ''
  return Array.isArray(d) ? d.join(', ') : String(d)
}

function asList(v: DraftValue | SettingScalar | SettingScalar[]): string[] {
  return Array.isArray(v) ? v.map(String) : [String(v)]
}

/**
 * Whether a field's draft value differs from the field's default. Unset
 * (undefined, empty text, an empty list) is the default; a value equal to the
 * default (the same number, text or list) is not a change.
 */
export function isChangedValue(f: ToolSettingField, v: DraftValue): boolean {
  if (v === undefined || v === '') return false
  if (Array.isArray(v) && v.length === 0) return false
  const d = f.defaultValue
  if (d === undefined) return true
  if (Array.isArray(v) || Array.isArray(d)) return asList(v).join('\n') !== asList(d).join('\n')
  if ((f.kind === 'integer' || f.kind === 'number') && typeof v === 'string') {
    const n = Number(v)
    return v.trim() === '' || !Number.isFinite(n) || n !== Number(d)
  }
  return String(v) !== String(d)
}

/** Whether a draft value is set at all (an override in the sensor layer). */
export function isSetValue(v: DraftValue): boolean {
  if (v === undefined || v === '') return false
  return !(Array.isArray(v) && v.length === 0)
}

/** The fields whose draft value differs from their default, in field order. */
export function changedFields(fields: ToolSettingField[], draft: Draft): ToolSettingField[] {
  return fields.filter((f) => isChangedValue(f, draft[f.key]))
}

/** A short name for a field in a summary: its native flag without dashes, or its key. */
export function shortName(f: ToolSettingField): string {
  return f.flag ? f.flag.replace(/^-+/, '') : f.key
}

/** A draft value as summary text. */
export function valueText(v: DraftValue): string {
  if (v === undefined) return ''
  return Array.isArray(v) ? v.join(',') : String(v)
}

/** How many changed options a tool summary names before it ends with "…". */
export const SUMMARY_ITEMS = 3

/**
 * The changed options of a summary ("rate-limit 300, timeout 20, …"):
 * at most SUMMARY_ITEMS, then an ellipsis.
 */
export function changeSummaryList(changed: ToolSettingField[], draft: Draft): string {
  const shown = changed
    .slice(0, SUMMARY_ITEMS)
    .map((f) => `${shortName(f)} ${valueText(draft[f.key])}`)
  if (changed.length > SUMMARY_ITEMS) shown.push('…')
  return shown.join(', ')
}

/**
 * Whether a field matches a search query (lower-case, trimmed): by key,
 * native flag or label.
 */
export function fieldMatches(f: ToolSettingField, label: string, q: string): boolean {
  if (q === '') return false
  return [f.key, f.flag ?? '', label].some((s) => s.toLowerCase().includes(q))
}
