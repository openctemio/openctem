import type { ScanConfig } from '@/lib/api/scan-types'
import { enTranslate, type Translate } from './translate'

/** Reason codes the API stores for a skipped scheduled occurrence. */
const REASON_KEYS: Record<string, string> = {
  platform_unavailable: 'scans.missed.reason.platformUnavailable',
  once_grace_exceeded: 'scans.missed.reason.onceGraceExceeded',
}

/** The reason in words; an unknown code reads as the generic reason. */
export function missedReasonLabel(reason: string | undefined, t: Translate = enTranslate): string {
  return t((reason && REASON_KEYS[reason]) || 'scans.missed.reason.generic')
}

/**
 * Whether the scan shows a "Missed" note: the API sent a missed occurrence
 * and the scan is still scheduled (a managed or disabled scan has nobody to
 * run it, and a manual scan has no schedule to miss).
 */
export function hasScheduleMissed(
  config: Pick<ScanConfig, 'last_missed_at' | 'schedule_type' | 'status'>
): boolean {
  return (
    !!config.last_missed_at && config.schedule_type !== 'manual' && config.status !== 'disabled'
  )
}
