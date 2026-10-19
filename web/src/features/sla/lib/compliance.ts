/**
 * The numbers of the SLA compliance page. Every number is one server-side
 * stats read over a filter, and the page's link for that number opens the
 * Findings page with the very same filter, so a tile and the list it opens
 * always agree. The population is the Findings page's default: the Open lens
 * (no closed findings, no pentest drafts), inside the caller's data scope.
 */

import type { FindingStatsFilters } from '@/features/findings/api/use-findings-api'

export type ComplianceTile = 'pastDue' | 'dueSoon' | 'onTrack' | 'open'

/** A breach is past due whatever the backend calls it: overdue or exceeded. */
export const PAST_DUE_STATUSES = ['overdue', 'exceeded']

const TILE_STATUSES: Record<ComplianceTile, string[] | undefined> = {
  pastDue: PAST_DUE_STATUSES,
  dueSoon: ['warning'],
  onTrack: ['on_track'],
  open: undefined,
}

export interface ComplianceFilter extends FindingStatsFilters {
  state: 'open'
}

export function tileFilter(tile: ComplianceTile): ComplianceFilter {
  const statuses = TILE_STATUSES[tile]
  return { state: 'open', ...(statuses ? { sla_statuses: statuses } : {}) }
}

export type AgingBucketKey = 'upTo7' | 'd8to30' | 'd31to90' | 'over90'

/** Past-due buckets by days since the deadline; together they cover every past-due finding. */
export const AGING_BUCKET_KEYS: AgingBucketKey[] = ['upTo7', 'd8to30', 'd31to90', 'over90']

const AGING_BOUNDS: Record<AgingBucketKey, { gt?: string; lte?: string }> = {
  upTo7: { gt: '-P7D' },
  d8to30: { lte: '-P7D', gt: '-P30D' },
  d31to90: { lte: '-P30D', gt: '-P90D' },
  over90: { lte: '-P90D' },
}

export function agingFilter(bucket: AgingBucketKey): ComplianceFilter {
  const b = AGING_BOUNDS[bucket]
  return {
    state: 'open',
    sla_statuses: PAST_DUE_STATUSES,
    ...(b.gt ? { sla_deadline_gt: b.gt } : {}),
    ...(b.lte ? { sla_deadline_lte: b.lte } : {}),
  }
}

/** The Findings page URL that lists exactly what a stats read over `filter` counts. */
export function findingsHref(filter: ComplianceFilter, extra?: { severity?: string }): string {
  const p = new URLSearchParams()
  p.set('state', filter.state)
  if (filter.sla_statuses?.length) p.set('sla_status', filter.sla_statuses.join(','))
  if (filter.sla_deadline_gt) p.set('sla_deadline_gt', filter.sla_deadline_gt)
  if (filter.sla_deadline_lte) p.set('sla_deadline_lte', filter.sla_deadline_lte)
  if (extra?.severity) p.set('severity', extra.severity)
  return `/findings?${p.toString()}`
}

/** Whole days a deadline is behind now; 0 for under a day or no/invalid deadline. */
export function daysPastDue(deadline?: string | null, now = Date.now()): number {
  if (!deadline) return 0
  const t = Date.parse(deadline)
  if (Number.isNaN(t) || t >= now) return 0
  return Math.floor((now - t) / 86_400_000)
}
