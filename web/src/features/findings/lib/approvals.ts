import { APPROVAL_STATUSES, type ApiApproval, type ApprovalStatus } from '../types'

/** A tab of the approvals page: one status, or every status. */
export type ApprovalTab = 'all' | ApprovalStatus

/** Tab counts from the server's per-status counts (already data-scoped). */
export function approvalTabCounts(
  statusCounts: Partial<Record<ApprovalStatus, number>> | undefined
): Record<ApprovalTab, number> {
  const counts = { all: 0 } as Record<ApprovalTab, number>
  for (const st of APPROVAL_STATUSES) {
    const n = statusCounts?.[st] ?? 0
    counts[st] = n
    counts.all += n
  }
  return counts
}

/** Only the requester may cancel a pending request (the server refuses anyone else). */
export function canCancelApproval(
  approval: Pick<ApiApproval, 'status' | 'requested_by'>,
  currentUserId: string | undefined
): boolean {
  return approval.status === 'pending' && !!currentUserId && approval.requested_by === currentUserId
}
