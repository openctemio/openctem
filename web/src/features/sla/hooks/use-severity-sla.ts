'use client'

import { useEffectiveSlaPolicy, type SlaPolicy } from '../api/use-sla-policies-api'
import { NO_SLA } from '../schemas/sla-policy-schema'

export type SlaSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/** Days of the severity's window in a policy; undefined when unknown or "no SLA". */
export function severityDays(
  policy:
    | Pick<SlaPolicy, 'critical_days' | 'high_days' | 'medium_days' | 'low_days' | 'info_days'>
    | undefined,
  severity: SlaSeverity
): number | undefined {
  const days = policy?.[`${severity}_days`]
  return typeof days === 'number' && days > NO_SLA ? days : undefined
}

/** The date `days` after `from`, as YYYY-MM-DD. */
export function slaDueDate(days: number, from: Date = new Date()): string {
  const d = new Date(from)
  d.setDate(d.getDate() + days)
  return d.toISOString().slice(0, 10)
}

/**
 * The severity window in days from the API (the asset's effective policy
 * when an asset is given, else the organization's; both fall back to the
 * platform defaults on the server). Undefined while loading, when the
 * caller may not read it, or when the severity has no SLA.
 */
export function useSeveritySlaDays(
  severity: SlaSeverity | undefined,
  assetId?: string | null
): number | undefined {
  const { data } = useEffectiveSlaPolicy(assetId)
  return severity ? severityDays(data, severity) : undefined
}
