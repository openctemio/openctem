import type { FindingStatsResponse } from '../api/finding-api.types'

/**
 * The findings page overview strip (research/81): page-level numbers over
 * every finding the caller may see, read from ONE stats response requested
 * with state=all. Total is the All tab's count and Open the Open tab's, from
 * the same by_state the tabs read, so a card and its tab always agree. A
 * field an older API does not send shows as '—' rather than a wrong number.
 */
export interface FindingsOverview {
  total: number | string
  open: number | string
  criticalOpen: number | string
  highOpen: number | string
  overdue: number | string
  kev: number | string
  awaitingVerification: number | string
}

const UNKNOWN = '—'

export function findingsOverview(stats: FindingStatsResponse | undefined): FindingsOverview {
  if (!stats) {
    return {
      total: 0,
      open: 0,
      criticalOpen: 0,
      highOpen: 0,
      overdue: 0,
      kev: 0,
      awaitingVerification: 0,
    }
  }
  const openBySeverity = stats.open_by_severity
  return {
    total: stats.by_state?.all ?? stats.total,
    open: stats.by_state?.open ?? UNKNOWN,
    criticalOpen: openBySeverity ? (openBySeverity.critical ?? 0) : UNKNOWN,
    highOpen: openBySeverity ? (openBySeverity.high ?? 0) : UNKNOWN,
    overdue: stats.sla_breached ?? UNKNOWN,
    kev: stats.kev_open ?? UNKNOWN,
    awaitingVerification: stats.awaiting_verification ?? UNKNOWN,
  }
}
