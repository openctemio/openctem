/**
 * Group exceptions: one approval decision covering the open findings of a
 * remediation task (api/docs/rfcs/RFC-111-approval-policy.md). The task asks
 * for it (preview, then request); the approvals inbox decides it once.
 */

'use client'

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { ApprovalStatus } from '../types/finding.types'
import type { ApprovalEvaluation, ApprovalTier, RiskClass } from '../lib/approval-policy'

export type GroupExceptionStatus = 'accepted' | 'false_positive'

/** Why the preview left a finding out of the group. */
export type GroupExceptionSkip = 'not_found' | 'cannot_move' | 'pending_request'

/** One open finding of the task in the preview. */
export interface GroupExceptionPreviewMember {
  finding_id: string
  title?: string
  severity?: string
  tier?: ApprovalTier
  risk_class?: RiskClass
  /** The member's own end (accepted): the requested end or its cap. */
  end?: string
  /** The requested end was past this member's cap, so it ends earlier. */
  shortened?: boolean
  skipped?: GroupExceptionSkip
}

/** POST .../exception/preview: how the group would be decided now. */
export interface GroupExceptionPreview {
  /** The group's evaluation: the highest member tier, never below peer. */
  evaluation: ApprovalEvaluation
  members: GroupExceptionPreviewMember[]
  included: number
  skipped: number
}

/** Body of the preview and of the request. */
export interface GroupExceptionInput {
  requested_status: GroupExceptionStatus
  closure_reason: string
  justification: string
  /** RFC 3339; accepted only. */
  expires_at?: string
  /**
   * Confirms a group above the bulk ceiling (the API answers 400
   * BULK_TOO_LARGE until it is sent).
   */
  approved?: boolean
}

/** A member request of a group exception. */
export interface ApprovalBatchMember {
  approval_id: string
  finding_id: string
  title?: string
  severity?: string
  status: ApprovalStatus
  expires_at?: string
}

/** A group exception. */
export interface ApprovalBatch {
  id: string
  source_type: string
  source_id: string
  source_title?: string
  requested_status: GroupExceptionStatus
  closure_reason: string
  justification: string
  expires_at?: string
  requested_by?: string
  tier: ApprovalTier
  risk_class: RiskClass
  approvals_required: number
  approvals_collected: number
  status: ApprovalStatus
  decide_by: string
  member_count: number
  decided_by?: string
  decided_at?: string
  rejection_reason?: string
  created_at: string
  /** Only on the detail read. */
  members?: ApprovalBatchMember[]
  /** Only on the approval that applied the group. */
  applied?: number
  /** Members canceled because their finding moved meanwhile. */
  canceled?: string[]
  /** Members whose end was cut to their cap at decision time. */
  shortened?: number
}

export interface ApprovalBatchList {
  data: ApprovalBatch[]
  total: number
  page: number
  per_page: number
}

const BATCHES = '/api/v1/approvals/batches'

function taskExceptionUrl(taskId: string): string {
  return `/api/v1/remediation/tasks/${encodeURIComponent(taskId)}/exception`
}

export function approvalBatchesUrl(
  page: number,
  perPage: number,
  status?: ApprovalStatus,
  sourceId?: string
): string {
  const p = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  if (status) p.set('status', status)
  if (sourceId) p.set('source_id', sourceId)
  return `${BATCHES}?${p.toString()}`
}

/** One page of the group exceptions the caller may see (every member in scope). */
export function useApprovalBatches(
  page: number,
  perPage: number,
  status?: ApprovalStatus,
  enabled = true,
  sourceId?: string
) {
  const { currentTenant } = useTenant()
  return useSWR<ApprovalBatchList>(
    currentTenant && enabled ? approvalBatchesUrl(page, perPage, status, sourceId) : null,
    get,
    { revalidateOnFocus: false, keepPreviousData: true }
  )
}

/** One group exception with its member requests. */
export function useApprovalBatch(id: string | null | undefined) {
  const { currentTenant } = useTenant()
  return useSWR<ApprovalBatch>(
    currentTenant && id ? `${BATCHES}/${encodeURIComponent(id)}` : null,
    get,
    { revalidateOnFocus: false }
  )
}

/**
 * The pending group exception of one task, if the caller can see it. The
 * server filters by the task (a task has at most one pending exception; the
 * request answers 409 when one exists).
 */
export function usePendingTaskException(taskId: string | undefined, enabled = true) {
  const { data, mutate, isLoading } = useApprovalBatches(
    1,
    1,
    'pending',
    !!taskId && enabled,
    taskId
  )
  const batch = data?.data.find((b) => b.source_id === taskId)
  return { batch, mutate, isLoading }
}

export const approvalBatchApi = {
  preview: (taskId: string, body: GroupExceptionInput) =>
    post<GroupExceptionPreview>(`${taskExceptionUrl(taskId)}/preview`, body),
  request: (taskId: string, body: GroupExceptionInput) =>
    post<ApprovalBatch>(taskExceptionUrl(taskId), body),
  /** 200 with status "pending" while more sign-offs are needed. */
  approve: (id: string) => post<ApprovalBatch>(`${BATCHES}/${encodeURIComponent(id)}/approve`, {}),
  reject: (id: string, reason: string) =>
    post<ApprovalBatch>(`${BATCHES}/${encodeURIComponent(id)}/reject`, { reason }),
  cancel: (id: string) => post<ApprovalBatch>(`${BATCHES}/${encodeURIComponent(id)}/cancel`, {}),
}
