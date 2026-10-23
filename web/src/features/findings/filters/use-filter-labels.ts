'use client'

import { useCallback } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useSeverityLabel } from '@/hooks/use-scale-labels'
import { SEVERITY_LEVELS, type SeverityLevel } from '@/lib/severity'
import { FINDING_STATUS_CONFIG } from '@/features/findings/types/finding.types'
import type { FindingStatus } from '@/features/findings'
import { humanize, type FieldContract, type FilterOp } from './model'

/** `-P7D` / `P30D` / `+P2W`: a duration from now, back (`-`) or ahead. */
const RELATIVE = /^([+-]?)P(\d+)([DWMY])$/

const UNIT_KEYS: Record<string, [string, string]> = {
  D: ['findings.filter.unit.day', '{count, plural, one {# day} other {# days}}'],
  W: ['findings.filter.unit.week', '{count, plural, one {# week} other {# weeks}}'],
  M: ['findings.filter.unit.month', '{count, plural, one {# month} other {# months}}'],
  Y: ['findings.filter.unit.year', '{count, plural, one {# year} other {# years}}'],
}

type OpKind = 'text' | 'number' | 'time'

function opKind(field: Pick<FieldContract, 'type'>): OpKind {
  if (field.type === 'date-time') return 'time'
  if (field.type === 'number' || field.type === 'integer') return 'number'
  return 'text'
}

const OP_DEFAULTS: Record<OpKind, Partial<Record<FilterOp, string>>> = {
  text: {
    in: 'is',
    eq: 'is',
    not_in: 'is not',
    ne: 'is not',
    contains: 'contains',
    is_null: 'is empty',
  },
  number: {
    in: 'is',
    eq: '=',
    not_in: 'is not',
    ne: '≠',
    gte: '≥',
    gt: '>',
    lte: '≤',
    lt: '<',
    is_null: 'is empty',
  },
  time: {
    gte: 'on or after',
    gt: 'after',
    lte: 'on or before',
    lt: 'before',
    is_null: 'is empty',
  },
}

/** Words for fields, operators and values of the findings filters, translated. */
export function useFilterLabels() {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()

  const fieldLabel = useCallback(
    (name: string) => t(`findings.filter.field.${name}`, humanize(name)),
    [t]
  )

  const opLabel = useCallback(
    (op: FilterOp, field: Pick<FieldContract, 'type'>) => {
      const kind = opKind(field)
      return t(`findings.filter.op.${kind}.${op}`, OP_DEFAULTS[kind][op] ?? op)
    },
    [t]
  )

  const relative = useCallback(
    (value: string): string | undefined => {
      const m = RELATIVE.exec(value)
      if (!m) return undefined
      const [, sign, n, unit] = m
      const [key, fallback] = UNIT_KEYS[unit]
      const span = t(key, fallback, { count: Number(n) })
      return sign === '-'
        ? t('findings.filter.rel.ago', '{span} ago', { span })
        : t('findings.filter.rel.ahead', 'in {span}', { span })
    },
    [t]
  )

  const valueLabel = useCallback(
    (field: Pick<FieldContract, 'name' | 'type'>, value: string): string => {
      if (field.type === 'boolean') {
        return value === 'true' ? t('common.yes', 'Yes') : t('common.no', 'No')
      }
      if (field.type === 'date-time') {
        const rel = relative(value)
        if (rel) return rel
        const d = new Date(value)
        return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString()
      }
      if (field.name === 'severity' && (SEVERITY_LEVELS as readonly string[]).includes(value)) {
        return severityLabel(value as SeverityLevel)
      }
      if (field.name === 'status') {
        const cfg = FINDING_STATUS_CONFIG[value as FindingStatus]
        return cfg ? t(cfg.labelKey, cfg.label) : humanize(value)
      }
      if (field.name === 'sla_status') {
        return t(`findings.sla.${value}`, humanize(value))
      }
      if (field.name === 'related_to' && value === 'me') {
        return t('findings.filter.value.me', 'Me')
      }
      if (field.type === 'enum') {
        return t(`findings.filter.value.${field.name}.${value}`, humanize(value))
      }
      if (field.type === 'id') return value.length > 12 ? `${value.slice(0, 8)}…` : value
      return value
    },
    [t, severityLabel, relative]
  )

  return { fieldLabel, opLabel, valueLabel, relative }
}
