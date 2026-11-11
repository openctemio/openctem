/**
 * Pure helpers of the compliance view: the pass rate in words and tone, and
 * the tone and label of each check result.
 */

import type { Tone } from '@/components/ui/tone-chip'
import type { MeterTone } from '@/features/shared/components/meter'
import type { ComplianceResult } from '../api/compliance-checks-api'

/** Results in display order: what needs work first. */
export const COMPLIANCE_RESULTS: ComplianceResult[] = [
  'fail',
  'manual',
  'error',
  'not_applicable',
  'pass',
]

export const RESULT_TONE: Record<ComplianceResult, Tone> = {
  fail: 'danger',
  manual: 'caution',
  error: 'neutral',
  not_applicable: 'quiet',
  pass: 'ok',
}

export const RESULT_TEXT: Record<ComplianceResult, string> = {
  fail: 'Failed',
  manual: 'Needs review',
  error: 'Could not run',
  not_applicable: 'Not applicable',
  pass: 'Passed',
}

/** The pass rate as a whole percentage, floored so 99.6 % never shows as 100 %; null stays null. */
export function passRatePercent(rate: number | null | undefined): number | null {
  if (rate === null || rate === undefined || Number.isNaN(rate)) return null
  return Math.floor(Math.min(1, Math.max(0, rate)) * 100)
}

/** Below 70 % destructive, below 90 % warning, else success. */
export function passRateTone(rate: number | null | undefined): MeterTone {
  const p = passRatePercent(rate)
  if (p === null) return 'default'
  if (p < 70) return 'destructive'
  if (p < 90) return 'warning'
  return 'success'
}
