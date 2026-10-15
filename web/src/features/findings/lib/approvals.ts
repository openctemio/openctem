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

/**
 * The viewer made this request: the four-eyes rule refuses their own
 * approval or rejection (the server is the authority; the inbox only says so).
 */
export function isOwnApproval(
  approval: Pick<ApiApproval, 'requested_by'>,
  currentUserId: string | undefined
): boolean {
  return !!currentUserId && !!approval.requested_by && approval.requested_by === currentUserId
}

/** Who made a request, for the inbox's Requester column. */
export type ApprovalRequester =
  | { kind: 'you' }
  | { kind: 'member'; name: string }
  | { kind: 'former' }
  | { kind: 'actor'; actor: string }

export function approvalRequester(
  approval: Pick<ApiApproval, 'requested_by' | 'requested_by_name' | 'requested_by_actor'>,
  currentUserId: string | undefined
): ApprovalRequester {
  if (approval.requested_by_actor) return { kind: 'actor', actor: approval.requested_by_actor }
  if (isOwnApproval(approval, currentUserId)) return { kind: 'you' }
  // The server names only current members of this organization.
  if (approval.requested_by_name) return { kind: 'member', name: approval.requested_by_name }
  return { kind: 'former' }
}
