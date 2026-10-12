'use client'

/**
 * Remediation window of a CTEM priority class, read from the API.
 *
 * The console keeps no copy of the windows: they come from the asset's
 * effective SLA policy when an asset is known, else from the organization's
 * (both fall back to the platform defaults on the server).
 */

import { useEffectiveSlaPolicy, type SlaPolicy } from '../api/use-sla-policies-api'

export type SlaPriorityClass = 'P0' | 'P1' | 'P2' | 'P3'

const PRIORITY_DAYS_KEY: Record<SlaPriorityClass, 'p0_days' | 'p1_days' | 'p2_days' | 'p3_days'> = {
  P0: 'p0_days',
  P1: 'p1_days',
  P2: 'p2_days',
  P3: 'p3_days',
}

/** Days of the class's window in a policy, or undefined when unknown. */
export function priorityClassDays(
  policy: Pick<SlaPolicy, 'p0_days' | 'p1_days' | 'p2_days' | 'p3_days'> | undefined,
  priorityClass: SlaPriorityClass
): number | undefined {
  const days = policy?.[PRIORITY_DAYS_KEY[priorityClass]]
  return typeof days === 'number' && days > 0 ? days : undefined
}

/** "1 day" / "5 days". */
export function formatSlaDays(days: number): string {
  return days === 1 ? '1 day' : `${days} days`
}

/** The class's window in days, from the API; undefined while loading or unreadable. */
export function usePriorityClassSlaDays(
  priorityClass: SlaPriorityClass,
  assetId?: string | null
): number | undefined {
  const { data } = useEffectiveSlaPolicy(assetId)
  return priorityClassDays(data, priorityClass)
}

interface PriorityClassSlaProps {
  priorityClass: SlaPriorityClass
  /** The asset whose policy applies; omit for the organization's windows. */
  assetId?: string | null
  /** `label` renders "SLA: 5 days"; `sentence` renders "fix within 5 days". */
  variant?: 'label' | 'sentence'
  className?: string
}

/** Renders nothing until the window is known. */
export function PriorityClassSla({
  priorityClass,
  assetId,
  variant = 'label',
  className,
}: PriorityClassSlaProps) {
  const days = usePriorityClassSlaDays(priorityClass, assetId)
  if (days === undefined) return null
  const text =
    variant === 'sentence' ? `fix within ${formatSlaDays(days)}` : `SLA: ${formatSlaDays(days)}`
  return (
    <span className={className} data-slot="priority-class-sla">
      {text}
    </span>
  )
}
