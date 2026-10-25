/**
 * The requests triage mode makes. No endpoint of its own: windows are pages
 * of the findings list API (the caller's scope applies on every read) and
 * decisions are the per-finding endpoints the finding page uses, with the
 * shown version as If-Match so a decision never overwrites someone else's.
 * Design: research/234 §5.2.
 */

import { get, patch, post } from '@/lib/api/client'
import { toDisplayText } from '@/lib/untrusted-text'
import { ifMatchRowVersion } from '../lib/finding-conflict'
import { TRIAGE_WINDOW, triageQuery, type TriageItem } from '../lib/triage-session'
import type { ApiFinding, ApiFindingListResponse } from './finding-api.types'
import { findingTransitionsKey, type FindingTransitions } from './use-finding-transitions'
import type { FindingStatus } from '../types'

export function toTriageItem(f: ApiFinding): TriageItem {
  return {
    id: f.id,
    title: toDisplayText(f.title || f.message || f.rule_name || f.rule_id || '', 200),
    status: f.status,
    priorityClass: f.priority_class,
    rank: f.rank,
    assetName: f.asset?.name ? toDisplayText(f.asset.name, 120) : undefined,
    rowVersion: f.row_version,
  }
}

/** The list URL of one window of a queue (page is 1-based). */
export function triageWindowUrl(query: string, page: number, perPage = TRIAGE_WINDOW): string {
  const q = new URLSearchParams(triageQuery(query))
  q.set('page', String(page))
  q.set('per_page', String(perPage))
  return `/api/v1/findings?${q.toString()}`
}

export interface TriageWindow {
  items: TriageItem[]
  total: number
  lastPage: boolean
}

export async function fetchTriageWindow(query: string, page: number): Promise<TriageWindow> {
  const res = await get<ApiFindingListResponse>(triageWindowUrl(query, page))
  const rows = res?.data ?? []
  const totalPages = res?.total_pages ?? 0
  return {
    items: rows.map(toTriageItem),
    total: res?.total ?? rows.length,
    lastPage: rows.length < TRIAGE_WINDOW || page >= totalPages,
  }
}

/** The caller's allowed moves of one finding (the lifecycle's own answer). */
export function fetchTransitions(findingId: string): Promise<FindingTransitions> {
  return get<FindingTransitions>(findingTransitionsKey(findingId))
}

export interface StatusWrite {
  status: FindingStatus
  resolution?: string
  sub_status_id?: string
  fields?: Record<string, string>
}

/** PATCH /findings/{id}/status, conditional on the version shown. */
export function writeFindingStatus(
  findingId: string,
  body: StatusWrite,
  rowVersion?: number
): Promise<ApiFinding> {
  return patch<ApiFinding>(
    `/api/v1/findings/${encodeURIComponent(findingId)}/status`,
    body,
    ifMatchRowVersion(rowVersion)
  )
}

/** POST /findings/{id}/assign (or unassign with null), conditional on the version shown. */
export function writeFindingAssignee(
  findingId: string,
  userId: string | null,
  rowVersion?: number
): Promise<ApiFinding> {
  const base = `/api/v1/findings/${encodeURIComponent(findingId)}`
  return userId
    ? post<ApiFinding>(`${base}/assign`, { user_id: userId }, ifMatchRowVersion(rowVersion))
    : post<ApiFinding>(`${base}/unassign`, {}, ifMatchRowVersion(rowVersion))
}

/** The finding as it is now (Undo writes on the current version, not the shown one). */
export function fetchFinding(findingId: string): Promise<ApiFinding> {
  return get<ApiFinding>(`/api/v1/findings/${encodeURIComponent(findingId)}`)
}

/** Withdraws a pending approval request (it stays on record as cancelled). */
export function cancelApproval(approvalId: string): Promise<unknown> {
  return post(`/api/v1/approvals/${encodeURIComponent(approvalId)}/cancel`, {})
}

/** "Retest now": a deterministic re-check of the finding's rule (findings:verify). */
export function requestRetest(findingId: string): Promise<unknown> {
  return post(`/api/v1/findings/${encodeURIComponent(findingId)}/retests`, {})
}
