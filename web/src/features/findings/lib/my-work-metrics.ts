import { buildFindingsQuery } from '@/features/findings/api/use-findings-api'
import type { FindingApiFilters } from '@/features/findings/api/finding-api.types'
import { FINDINGS_LIST_HIDDEN_STATUSES } from './list-defaults'

/**
 * My work's figures. Each figure is counted with one filter object and its
 * drill link is built from that same object through the list query codec, so
 * the number on the page is the total of the list it opens.
 *
 * The Findings list hides pentest drafts by default and applies the Open
 * state lens, so both are part of every filter here.
 */

export type MyWorkMetricKey = 'open' | 'critical' | 'overdue'

const BASE: FindingApiFilters = {
  assigned_to_me: true,
  state: 'open',
  exclude_statuses: [...FINDINGS_LIST_HIDDEN_STATUSES],
}

/** The filter that counts (and lists) each figure. */
export const MY_WORK_METRIC_FILTERS: Record<MyWorkMetricKey, FindingApiFilters> = {
  open: { ...BASE },
  critical: { ...BASE, severities: ['critical', 'high'] },
  overdue: { ...BASE, sla_statuses: ['overdue', 'exceeded'] },
}

/**
 * The Findings page link for a filter. Paging and sort are page state, and the
 * list excludes its hidden statuses on its own, so neither is in the link.
 */
export function findingsDrillUrl(filters: FindingApiFilters): string {
  const query = buildFindingsQuery({
    ...filters,
    page: undefined,
    per_page: undefined,
    sort: undefined,
    exclude_statuses: undefined,
  })
  const qs = query.toString()
  return qs ? `/findings?${qs}` : '/findings'
}
