/**
 * My Work's queues (research 229 §8.5, api/docs/architecture/my-work.md).
 * Every queue is a view on the caller's own rows, read through an endpoint
 * that already applies the tenant and the caller's data scope:
 *
 * - finding queues are quick views (`GET /findings/quick-views`): the count
 *   and the list compile the same `params`, so a tab's count is the total of
 *   the list under it and of the Findings page it links to;
 * - approval queues are `GET /approvals?queue=review|requested`, whose
 *   `queue_counts` count the same rows the list pages through;
 * - My tasks is the remediation task list with `assignee=me`.
 */

import type { QuickView } from '@/features/findings/lib/quick-views'

export const MY_WORK_TABS = [
  'assigned',
  'team',
  'review',
  'requested',
  'expiring',
  'tasks',
] as const
export type MyWorkTab = (typeof MY_WORK_TABS)[number]

export type FindingQueueTab = 'assigned' | 'team' | 'expiring'
export type ApprovalQueueTab = 'review' | 'requested'

/** The quick view behind each finding queue. */
export const FINDING_QUEUE_VIEW: Record<FindingQueueTab, string> = {
  assigned: 'my_queue',
  team: 'my_team',
  expiring: 'my_accepted_expiring',
}

/** The "SLA due in 72 hours" chip on Assigned to me (overdue included). */
export const DUE_SOON_VIEW = 'my_due_soon'
/** Triage mode's queue: findings still to be decided. */
export const NEEDS_TRIAGE_VIEW = 'needs_triage'

/** How each finding queue is ordered (a list sort the API accepts). */
export const FINDING_QUEUE_SORT: Record<FindingQueueTab, string> = {
  // The remediation owner works by deadline: the nearest SLA first.
  assigned: 'sla_deadline,priority_class,-created_at',
  team: 'priority_class,severity,-created_at',
  expiring: 'acceptance_expires_at',
}

/** Rows a queue shows; "View all" opens the full list. */
export const QUEUE_SIZE = 15

export function isFindingQueueTab(tab: MyWorkTab): tab is FindingQueueTab {
  return tab === 'assigned' || tab === 'team' || tab === 'expiring'
}

export function isApprovalQueueTab(tab: MyWorkTab): tab is ApprovalQueueTab {
  return tab === 'review' || tab === 'requested'
}

/** The tab named in the URL when the caller has it, else the first one they have. */
export function parseTab(raw: string | null, available: readonly MyWorkTab[]): MyWorkTab {
  const hit = available.find((t) => t === raw)
  return hit ?? available[0] ?? 'assigned'
}

/** The quick view of a key, when the API returned it. */
export function viewOf(
  views: readonly QuickView[] | undefined,
  key: string
): QuickView | undefined {
  return views?.find((v) => v.key === key)
}

/**
 * The findings list request for a view's params: the view's own filter plus
 * paging and order only, so its total is the view's count.
 */
export function findingsQueueEndpoint(params: string, sort: string, perPage = QUEUE_SIZE): string {
  const q = new URLSearchParams(params)
  q.set('sort', sort)
  q.set('page', '1')
  q.set('per_page', String(perPage))
  return `/api/v1/findings?${q.toString()}`
}

/** The approval queue request (pending requests, newest first). */
export function approvalQueueEndpoint(queue: ApprovalQueueTab, perPage: number): string {
  const q = new URLSearchParams({
    queue,
    status: 'pending',
    page: '1',
    per_page: String(perPage),
  })
  return `/api/v1/approvals?${q.toString()}`
}

/** Days an accepted risk would last, from the request to its end (rounded). */
export function acceptanceDays(createdAt?: string, expiresAt?: string): number | null {
  if (!createdAt || !expiresAt) return null
  const ms = new Date(expiresAt).getTime() - new Date(createdAt).getTime()
  if (!Number.isFinite(ms) || ms <= 0) return null
  return Math.round(ms / 86_400_000)
}

/** The approval-policy reasons the console can name ("changed since request"). */
export const CHANGE_REASONS = [
  'kev',
  'severity_critical',
  'severity_high',
  'priority_p0',
  'priority_p1',
  'exploit_validated',
  'epss_at_or_above_threshold',
  'crown_jewel',
  'internet_exposed',
] as const
