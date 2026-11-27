/**
 * Priority rule conditions: the fields the API evaluates
 * (server/pkg/domain/vulnerability/priority_rule.go), their operators, and the
 * one formatter that reads a stored condition as a plain sentence in the
 * reader's language ("Listed in KEV", "EPSS score is at least 50%"). The
 * rules list, the editor and the dry-run preview all use it, so a condition
 * is never shown as code ("is_in_kev = true").
 */

import { ASSET_CRITICALITY_LEVELS, CRITICALITY_LABELS } from '@/lib/criticality'
import { SEVERITY_LABELS, SEVERITY_LEVELS } from '@/lib/severity'
import { EXPOSURE_LEVEL_LABELS } from '@/features/assets/types/asset.types'

export type FieldKey =
  | 'is_in_kev'
  | 'is_reachable'
  | 'asset_is_crown_jewel'
  | 'epss_score'
  | 'severity'
  | 'asset_criticality'
  | 'asset_exposure'

export type FieldType = 'bool' | 'float' | 'string'

export type Operator = 'eq' | 'neq' | 'gte' | 'lte' | 'in'

export interface Condition {
  field: FieldKey
  operator: Operator
  value: unknown
}

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

interface FieldConfig {
  /** English field name (the catalog key is prioritization.rules.field.<field>). */
  fallback: string
  type: FieldType
  /** Allowed values of a string field, with their catalog prefix and English words. */
  options?: readonly string[]
  optionKeyPrefix?: string
  optionLabels?: Record<string, string>
}

export const FIELD_CONFIG: Record<FieldKey, FieldConfig> = {
  is_in_kev: { fallback: 'Is in KEV catalog', type: 'bool' },
  is_reachable: { fallback: 'Is reachable', type: 'bool' },
  asset_is_crown_jewel: { fallback: 'Asset is crown jewel', type: 'bool' },
  epss_score: { fallback: 'EPSS score', type: 'float' },
  severity: {
    fallback: 'Severity',
    type: 'string',
    options: SEVERITY_LEVELS,
    optionKeyPrefix: 'severity',
    optionLabels: SEVERITY_LABELS,
  },
  asset_criticality: {
    fallback: 'Asset criticality',
    type: 'string',
    options: ASSET_CRITICALITY_LEVELS,
    optionKeyPrefix: 'criticality',
    optionLabels: CRITICALITY_LABELS,
  },
  asset_exposure: {
    fallback: 'Asset exposure',
    type: 'string',
    options: Object.keys(EXPOSURE_LEVEL_LABELS),
    optionKeyPrefix: 'assets.exposure',
    optionLabels: EXPOSURE_LEVEL_LABELS,
  },
}

/** A yes/no condition as a sentence, when it holds and when it does not. */
const BOOL_SENTENCE: Record<string, [string, string]> = {
  is_in_kev: ['Listed in KEV', 'Not listed in KEV'],
  is_reachable: ['Reachable', 'Not reachable'],
  asset_is_crown_jewel: ['On a crown jewel asset', 'Not on a crown jewel asset'],
}

/** The English words of each operator (catalog: prioritization.rules.op.<op>). */
export const OPERATOR_FALLBACK: Record<Operator, string> = {
  eq: 'is',
  neq: 'is not',
  gte: 'is at least',
  lte: 'is at most',
  in: 'is one of',
}

export function isKnownField(field: string): field is FieldKey {
  return Object.prototype.hasOwnProperty.call(FIELD_CONFIG, field)
}

export function operatorsFor(type: FieldType): Operator[] {
  switch (type) {
    case 'bool':
      return ['eq', 'neq']
    case 'float':
      return ['eq', 'gte', 'lte']
    case 'string':
      return ['eq', 'neq', 'in']
  }
}

export function emptyConditionFor(field: FieldKey): Condition {
  const type = FIELD_CONFIG[field]?.type ?? 'string'
  const ops = operatorsFor(type)
  let value: unknown = ''
  if (type === 'bool') value = true
  else if (type === 'float') value = 0
  return { field, operator: ops[0], value }
}

export function fieldLabel(field: string, t: Translate): string {
  const cfg = isKnownField(field) ? FIELD_CONFIG[field] : undefined
  return t(`prioritization.rules.field.${field}`, cfg?.fallback ?? field)
}

export function operatorLabel(op: Operator, t: Translate): string {
  return t(`prioritization.rules.op.${op}`, OPERATOR_FALLBACK[op] ?? op)
}

/** One allowed value of a string field in words ("critical" -> "Critical"). */
export function optionLabel(field: FieldKey, value: string, t: Translate): string {
  const cfg = FIELD_CONFIG[field]
  if (!cfg?.optionKeyPrefix) return value
  return t(`${cfg.optionKeyPrefix}.${value}`, cfg.optionLabels?.[value] ?? value)
}

function percent(value: number, locale: string): string {
  try {
    return new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 1 }).format(
      value
    )
  } catch {
    return `${Math.round(value * 1000) / 10}%`
  }
}

function orList(items: string[], locale: string): string {
  try {
    return new Intl.ListFormat(locale, { type: 'disjunction' }).format(items)
  } catch {
    return items.join(', ')
  }
}

function asList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v))
  if (typeof value === 'string')
    return value
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  return []
}

/**
 * A stored condition as a plain sentence in the reader's language. A field
 * this build does not know (a newer server) reads as its name, operator and
 * value, never as nothing.
 */
export function describeCondition(c: Condition, t: Translate, locale: string): string {
  const field = String(c.field)
  if (!isKnownField(field)) {
    const value = Array.isArray(c.value) ? c.value.join(', ') : String(c.value ?? '')
    return `${field} ${OPERATOR_FALLBACK[c.operator] ?? c.operator} ${value}`.trim()
  }
  const cfg = FIELD_CONFIG[field]

  if (cfg.type === 'bool') {
    // "is_in_kev != false" means the same as "is_in_kev = true".
    const positive = Boolean(c.value) === (c.operator !== 'neq')
    return t(
      `prioritization.rules.sentence.${field}.${positive ? 'yes' : 'no'}`,
      BOOL_SENTENCE[field]?.[positive ? 0 : 1] ?? cfg.fallback
    )
  }

  const name = fieldLabel(field, t)
  if (cfg.type === 'float') {
    const n = typeof c.value === 'number' ? c.value : Number(c.value)
    const shown = Number.isFinite(n)
      ? field === 'epss_score'
        ? percent(n, locale)
        : String(n)
      : String(c.value ?? '')
    const key = c.operator === 'gte' ? 'atLeast' : c.operator === 'lte' ? 'atMost' : 'is'
    const fallback =
      key === 'atLeast'
        ? '{field} is at least {value}'
        : key === 'atMost'
          ? '{field} is at most {value}'
          : '{field} is {value}'
    return t(`prioritization.rules.sentence.${key}`, fallback, { field: name, value: shown })
  }

  if (c.operator === 'in') {
    const values = asList(c.value).map((v) => optionLabel(field, v, t))
    return t('prioritization.rules.sentence.oneOf', '{field} is {value}', {
      field: name,
      value: orList(values, locale),
    })
  }
  const value = optionLabel(field, String(c.value ?? ''), t)
  return c.operator === 'neq'
    ? t('prioritization.rules.sentence.isNot', '{field} is not {value}', { field: name, value })
    : t('prioritization.rules.sentence.is', '{field} is {value}', { field: name, value })
}
