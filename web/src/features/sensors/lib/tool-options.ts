/**
 * A tool's options, read from the configuration schema of its tool manifest
 * (`descriptor.config`, the closed JSON Schema subset of the CTIS settings
 * contract) as the sensor reported it. The descriptor is a claim from the
 * sensor: every field is checked for its type here, unknown or malformed
 * parts are skipped, and every string is rendered as text.
 *
 * Common options (`x-octm-common`: timeout, rate, concurrency, retries) mean
 * the same thing for every tool and come first; the others are specific to
 * the tool.
 */

/** The common tool options, in display order (CTIS tooloption). */
export const COMMON_OPTIONS = ['timeout', 'rate', 'concurrency', 'retries'] as const
export type CommonOption = (typeof COMMON_OPTIONS)[number]

/** Safety class of a non-default value (x-octm-tier). */
export type OptionSafety = 'safe' | 'impact' | 'dangerous'

export interface ToolOption {
  /** The key ("rate_limit"), "group.key" for a key of a group. */
  key: string
  type: 'boolean' | 'integer' | 'number' | 'string' | 'array' | ''
  /** The common option the key is, if any. */
  common?: CommonOption
  /** The tool's native flag ("-rate-limit"). */
  flag?: string
  title?: string
  description?: string
  defaultValue?: string
  minimum?: number
  maximum?: number
  /** Allowed values (an array's item values for an array). */
  values?: string[]
  /** Who may set it: only the sensor's configuration, or a scan too. */
  scope: 'sensor' | 'scan'
  safety: OptionSafety
  group?: string
  order: number
}

/** Bounds on what a hostile descriptor can make the page render. */
const MAX_OPTIONS = 64
const MAX_TEXT = 500
const MAX_VALUES = 32

const SAFETY: Record<string, OptionSafety> = { T0: 'safe', T1: 'impact', T2: 'dangerous' }
const TYPES = new Set(['boolean', 'integer', 'number', 'string', 'array'])
const FLAG_RE = /^--?[A-Za-z][A-Za-z0-9-]{0,47}$/

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

function scalarText(v: unknown): string | undefined {
  if (typeof v === 'string') return text(v)
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  if (Array.isArray(v)) {
    const parts = v
      .slice(0, MAX_VALUES)
      .map(scalarText)
      .filter((x): x is string => !!x)
    return parts.length > 0 ? text(parts.join(', ')) : undefined
  }
  return undefined
}

function valueList(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined
  const out = v
    .slice(0, MAX_VALUES)
    .map(scalarText)
    .filter((x): x is string => !!x)
  return out.length > 0 ? out : undefined
}

function readOption(key: string, raw: Record<string, unknown>, group?: string): ToolOption {
  const type = typeof raw.type === 'string' && TYPES.has(raw.type) ? raw.type : ''
  const common =
    typeof raw['x-octm-common'] === 'string' &&
    (COMMON_OPTIONS as readonly string[]).includes(raw['x-octm-common'])
      ? (raw['x-octm-common'] as CommonOption)
      : undefined
  const flag =
    typeof raw['x-octm-flag'] === 'string' && FLAG_RE.test(raw['x-octm-flag'])
      ? raw['x-octm-flag']
      : undefined
  const items = isObject(raw.items) ? raw.items : undefined
  return {
    key,
    type: type as ToolOption['type'],
    common,
    flag,
    title: text(raw.title),
    description: text(raw.description),
    defaultValue: scalarText(raw.default),
    minimum: num(raw.minimum),
    maximum: num(raw.maximum),
    values: valueList(raw.enum) ?? (items ? valueList(items.enum) : undefined),
    scope: raw['x-octm-scope'] === 'scan' ? 'scan' : 'sensor',
    safety: SAFETY[typeof raw['x-octm-tier'] === 'string' ? raw['x-octm-tier'] : ''] ?? 'safe',
    group,
    order: num(raw['x-octm-order']) ?? 0,
  }
}

function commonRank(o: ToolOption): number {
  return o.common ? COMMON_OPTIONS.indexOf(o.common) : COMMON_OPTIONS.length
}

/**
 * The options a tool's descriptor declares, common options first (in
 * COMMON_OPTIONS order), then the tool's own by group, order and key.
 * Returns [] for a descriptor without a configuration schema.
 */
export function toolOptions(descriptor: unknown): ToolOption[] {
  if (!isObject(descriptor) || !isObject(descriptor.config)) return []
  const props = descriptor.config.properties
  if (!isObject(props)) return []
  const out: ToolOption[] = []
  for (const [key, raw] of Object.entries(props)) {
    if (out.length >= MAX_OPTIONS) break
    if (!isObject(raw)) continue
    if (raw.type === 'object' && isObject(raw.properties)) {
      const group = text(raw.title) ?? key
      for (const [sub, subRaw] of Object.entries(raw.properties)) {
        if (out.length >= MAX_OPTIONS) break
        if (isObject(subRaw)) out.push(readOption(`${key}.${sub}`, subRaw, group))
      }
      continue
    }
    out.push(readOption(key, raw, text(raw['x-octm-group'])))
  }
  return out.sort(
    (a, b) =>
      commonRank(a) - commonRank(b) ||
      (a.group ?? '').localeCompare(b.group ?? '') ||
      a.order - b.order ||
      a.key.localeCompare(b.key)
  )
}

/** "1–300" style bounds, or "" when the option has none. */
export function boundsText(o: ToolOption): string {
  if (o.minimum !== undefined && o.maximum !== undefined) return `${o.minimum}–${o.maximum}`
  if (o.minimum !== undefined) return `≥ ${o.minimum}`
  if (o.maximum !== undefined) return `≤ ${o.maximum}`
  return ''
}
