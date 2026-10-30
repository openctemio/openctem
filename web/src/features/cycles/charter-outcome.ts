/**
 * Presentation helpers for the close-time charter evaluation
 * (`charter_evaluation` on a CTEM cycle). The API does the judging; these only
 * turn its numbers into readable text.
 */

import type { HealthState } from '@/lib/health-colors'
import type { useTranslation } from '@/context/i18n-provider'
import type { CharterEvaluation, CriterionEvaluation, CriterionOutcome } from './types'

export const OUTCOME_LABEL: Record<CriterionOutcome, string> = {
  met: 'Met',
  unmet: 'Unmet',
  not_measurable: 'Not measurable',
}

/** A criterion's verdict is computed by the platform, so it reads as a health state. */
export const OUTCOME_HEALTH: Record<CriterionOutcome, HealthState> = {
  met: 'ok',
  unmet: 'down',
  not_measurable: 'unknown',
}

const COMPARATOR_SYMBOL: Record<string, string> = {
  '<=': '≤',
  '<': '<',
  '>=': '≥',
  '>': '>',
  '=': '=',
}

const round = (v: number, digits = 2) => {
  const f = 10 ** digits
  return Math.round(v * f) / f
}

/** Formats a value in the metric's base unit (hours, count, percent, score). */
export function formatCriterionValue(value: number, unit?: string): string {
  switch (unit) {
    case 'hours':
      // Hours read badly past two days; switch to days there.
      if (Math.abs(value) >= 48) {
        const days = round(value / 24, 1)
        return `${days} ${days === 1 ? 'day' : 'days'}`
      }
      return `${round(value, 1)} h`
    case 'percent':
      return `${round(value, 1)}%`
    default:
      return `${round(value)}`
  }
}

/** "≤ 1 day" — the target as the API interpreted it. Empty when unparsed. */
export function formatThreshold(c: CriterionEvaluation): string {
  if (c.threshold === undefined || !c.comparator) return ''
  const symbol = COMPARATOR_SYMBOL[c.comparator] ?? c.comparator
  return `${symbol} ${formatCriterionValue(c.threshold, c.unit)}`
}

/**
 * One-line explanation under a criterion: the measured value against the
 * interpreted target, or why it could not be measured.
 */
export function describeCriterion(c: CriterionEvaluation): string {
  if (c.outcome === 'not_measurable' || c.actual === undefined) {
    return c.reason ? capitalize(c.reason) : 'Could not be measured'
  }
  const target = formatThreshold(c)
  const actual = formatCriterionValue(c.actual, c.unit)
  return target ? `Measured ${actual}, target ${target}` : `Measured ${actual}`
}

type Translate = ReturnType<typeof useTranslation>['t']

/**
 * "2 of 3 measurable criteria met": the table cell / toast summary. With `t`
 * the text comes from the catalog; without it, English.
 */
export function summarizeEvaluation(
  ev: CharterEvaluation | undefined | null,
  t?: Translate
): string | null {
  if (!ev) return null
  const met = ev.met ?? 0
  const measurable = met + (ev.unmet ?? 0)
  if (measurable === 0) {
    if ((ev.criteria?.length ?? 0) === 0) return null
    return t ? t('scoping.cycle.noMeasurable', 'No measurable criteria') : 'No measurable criteria'
  }
  return t
    ? t('scoping.cycle.metOf', '{met} of {measurable} met', { met, measurable })
    : `${met} of ${measurable} met`
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}
