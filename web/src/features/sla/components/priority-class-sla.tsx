'use client'

/**
 * Remediation window of a CTEM priority class, read from the API.
 *
 * The console keeps no copy of the windows: they come from the asset's
 * effective SLA policy when an asset is known, else from the organization's
 * (both fall back to the platform defaults on the server).
 */

import { useTranslation } from '@/context/i18n-provider'
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

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** "1 day" / "5 days". */
export function formatSlaDays(days: number, t?: Translate): string {
  if (!t) return days === 1 ? '1 day' : `${days} days`
  return days === 1
    ? t('findings.sla.dayOne', '1 day')
    : t('findings.sla.dayOther', '{count} days', { count: days })
}

const SEVERITY_DAYS_KEY = {
  critical: 'critical_days',
  high: 'high_days',
  medium: 'medium_days',
  low: 'low_days',
} as const

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
  /**
   * The finding's severity. With it the sentence says what the window is
   * based on when the severity's own window differs (a critical finding at
   * P2 gets the P2 window, not the critical one).
   */
  severity?: string
  /** `label` renders "SLA: 5 days"; `sentence` renders "fix within 5 days". */
  variant?: 'label' | 'sentence'
  className?: string
}

/** Renders nothing until the window is known. */
/**
 * Why the deadline is what it is, when the severity's own window differs:
 * "The deadline follows the priority (P2: 15 days), not the severity
 * (critical: 2 days)." Undefined while loading or when they agree.
 */
export function usePrioritySlaBasis(
  priorityClass: SlaPriorityClass,
  assetId: string | null | undefined,
  severity: string | undefined
): string | undefined {
  const { t } = useTranslation()
  const { data } = useEffectiveSlaPolicy(assetId)
  return slaBasis(t, data, priorityClass, severity)
}

function slaBasis(
  t: Translate,
  data: Partial<SlaPolicy> | undefined,
  priorityClass: SlaPriorityClass,
  severity: string | undefined
): string | undefined {
  const days = priorityClassDays(data as SlaPolicy | undefined, priorityClass)
  const sevKey = severity
    ? SEVERITY_DAYS_KEY[severity as keyof typeof SEVERITY_DAYS_KEY]
    : undefined
  const sevDays = sevKey ? data?.[sevKey] : undefined
  if (days === undefined || typeof sevDays !== 'number' || sevDays <= 0 || sevDays === days) {
    return undefined
  }
  return t(
    'findings.sla.basis',
    'The deadline follows the priority ({priority}: {window}), not the severity ({severity}: {severityWindow}).',
    {
      priority: priorityClass,
      window: formatSlaDays(days, t),
      severity: severity ?? '',
      severityWindow: formatSlaDays(sevDays, t),
    }
  )
}

export function PriorityClassSla({
  priorityClass,
  assetId,
  variant = 'label',
  severity,
  className,
}: PriorityClassSlaProps) {
  const { t } = useTranslation()
  const { data } = useEffectiveSlaPolicy(assetId)
  const days = priorityClassDays(data, priorityClass)
  if (days === undefined) return null
  const window = formatSlaDays(days, t)
  const text =
    variant === 'sentence'
      ? t('findings.sla.fixWithin', 'fix within {window}', { window })
      : t('findings.sla.label', 'SLA: {window}', { window })
  const basis = slaBasis(t, data, priorityClass, severity)
  return (
    <span className={className} data-slot="priority-class-sla" title={basis}>
      {text}
    </span>
  )
}
