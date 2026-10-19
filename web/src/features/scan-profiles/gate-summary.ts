import type { QualityGate } from '@/lib/api/scan-profile-types'

/** One-line summary of a pass/fail rule, e.g. "Fails on critical, high". */
export function gateSummary(gate: QualityGate, t: (key: string) => string): string {
  if (!gate.enabled) return t('scans.profiles.rule.off')
  const parts: string[] = []
  if (gate.fail_on_critical) parts.push(t('scans.profiles.rule.critical'))
  if (gate.fail_on_high) parts.push(t('scans.profiles.rule.high'))
  if (gate.max_medium >= 0) parts.push(`${t('scans.profiles.rule.medium')} ≤ ${gate.max_medium}`)
  if (gate.max_total >= 0) parts.push(`${t('scans.profiles.rule.total')} ≤ ${gate.max_total}`)
  return parts.length
    ? `${t('scans.profiles.rule.failsOn')} ${parts.join(', ')}`
    : t('scans.profiles.rule.on')
}
